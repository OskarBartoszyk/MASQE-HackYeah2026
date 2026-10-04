import json
from pathlib import Path
from faster_whisper import WhisperModel

model = WhisperModel('base', device='cpu', compute_type='int8', local_files_only=True)
segments, info = model.transcribe('/Users/oskar/Downloads/New tts node (2).mp3', language='en', word_timestamps=True, beam_size=5, initial_prompt='MASQE. Adam. CRM. Ghost Shell. Personal data. Credentials.')
result = []
for s in segments:
    result.append({'start':s.start,'end':s.end,'text':s.text,'words':[{'start':w.start,'end':w.end,'word':w.word} for w in s.words]})
    print(f'{s.start:.2f}-{s.end:.2f} {s.text}', flush=True)
Path('/Users/oskar/Desktop/HackYeah2026/tmp/video/alignment.json').write_text(json.dumps(result, indent=2))
