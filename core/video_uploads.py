"""Decode and transcode staff uploads; never trust extensions or browser MIME."""
import os
import subprocess
import tempfile
import threading
import struct
from pathlib import Path
from uuid import uuid4

import imageio_ffmpeg
from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.files.base import ContentFile

_slots = threading.BoundedSemaphore(1)


def mp4_duration(path):
    def boxes(stream, end):
        while stream.tell() + 8 <= end:
            start = stream.tell()
            size, kind = struct.unpack('>I4s', stream.read(8))
            if size < 8 or start + size > end:
                raise ValueError('Invalid MP4 box')
            yield kind, start + size
            stream.seek(start + size)
    with open(path, 'rb') as stream:
        for kind, end in boxes(stream, Path(path).stat().st_size):
            if kind == b'moov':
                for child, child_end in boxes(stream, end):
                    if child == b'mvhd':
                        version = stream.read(1)[0]
                        stream.read(3 + (16 if version == 1 else 8))
                        timescale = struct.unpack('>I', stream.read(4))[0]
                        duration = struct.unpack('>Q' if version == 1 else '>I', stream.read(8 if version == 1 else 4))[0]
                        return duration / timescale
    raise ValueError('Missing MP4 duration')


def video_upload_to(instance, filename):
    return f'videos/{uuid4().hex}.mp4'


def normalize_video(upload):
    if not upload or getattr(upload, '_committed', False):
        return upload
    source = getattr(upload, 'file', upload)
    if getattr(source, '_normalized_video', False):
        return upload
    if upload.size > settings.MAX_UPLOAD_VIDEO_BYTES:
        raise ValidationError('Видео должно быть не больше 100 МБ.')
    if Path(upload.name).suffix.lower() not in {'.mp4', '.webm', '.mov'}:
        raise ValidationError('Загрузите MP4, WebM или MOV. Видео будет преобразовано в MP4.')
    if not _slots.acquire(blocking=False):
        raise ValidationError('Обрабатывается другое видео. Повторите загрузку позже.')
    try:
        with tempfile.TemporaryDirectory(prefix='plit-video-') as work:
            input_path = Path(work) / 'input'
            output_path = Path(work) / 'output.mp4'
            upload.seek(0)
            total = 0
            with input_path.open('wb') as target:
                for chunk in upload.chunks():
                    total += len(chunk)
                    if total > settings.MAX_UPLOAD_VIDEO_BYTES:
                        raise ValidationError('Видео должно быть не больше 100 МБ.')
                    target.write(chunk)
            executable = imageio_ffmpeg.get_ffmpeg_exe()
            # Allow only file-based containers. No playlists, HTTP, concat or
            # external resources. Child receives no application secrets.
            command = [executable, '-nostdin', '-hide_banner', '-loglevel', 'error',
                       '-xerror', '-max_alloc', '67108864', '-threads', '1',
                       '-protocol_whitelist', 'file', '-format_whitelist', 'mov,matroska,webm',
                       '-i', str(input_path), '-map', '0:v:0', '-map', '0:a:0?',
                       '-map_metadata', '-1', '-map_chapters', '-1', '-sn', '-dn',
                       '-vf', 'scale=w=1280:h=720:force_original_aspect_ratio=decrease:force_divisible_by=2',
                       '-c:v', 'libx264', '-threads', '1', '-preset', 'fast', '-crf', '25',
                       '-pix_fmt', 'yuv420p', '-r', '30', '-c:a', 'aac', '-b:a', '128k',
                       '-t', '121', '-fs', str(settings.MAX_UPLOAD_VIDEO_BYTES + 65536),
                       '-movflags', '+faststart', '-y', str(output_path)]
            env = {key: os.environ[key] for key in ('SYSTEMROOT', 'WINDIR', 'TEMP', 'TMP') if key in os.environ}
            # Discard decoder diagnostics: may contain uploaded metadata/paths.
            subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=45, check=True,
                           cwd=work, env=env, creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
            if not output_path.exists() or not 100 < output_path.stat().st_size <= settings.MAX_UPLOAD_VIDEO_BYTES:
                raise ValidationError('Не удалось обработать видео в пределах 100 МБ.')
            if not 0 < mp4_duration(output_path) <= 120:
                raise ValidationError('Видео должно длиться не больше 2 минут.')
            result = ContentFile(output_path.read_bytes(), name=f'{uuid4().hex}.mp4')
            result._normalized_video = True
            return result
    except (OSError, ValueError, RuntimeError, ZeroDivisionError, struct.error, subprocess.SubprocessError):
        raise ValidationError('Видео повреждено, не поддерживается или слишком сложно для обработки. Используйте короткий MP4.') from None
    finally:
        upload.seek(0)
        _slots.release()
