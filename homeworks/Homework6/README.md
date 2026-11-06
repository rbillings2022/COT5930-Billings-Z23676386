# Social Engineering Threat Detector

## Run the application

From the Homework6 directory:

- `uv run homework6`

The backend serves the frontend automatically at:

- `http://127.0.0.1:8000/`

If port 8000 is already in use, the server automatically tries the next available port.

## Notes

- The backend accepts JSON payloads at `/api/social-engineering-analysis`.
- Frontend uploads accept `.txt` and `.eml` files only.
- The app includes prompt-injection blocking and a heuristic threat score fallback when the local model is unavailable.
