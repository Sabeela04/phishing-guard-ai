# Phishing Guard AI Backend

## Windows setup

Open Command Prompt in this `backend` folder:

```bash
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
uvicorn main:app --reload
```

Backend:
http://127.0.0.1:8000

Interactive API documentation:
http://127.0.0.1:8000/docs

## API

POST `/analyze`

Example JSON:

```json
{
  "content": "URGENT! Verify your account at http://secure-bank-login-example.com/verify",
  "input_type": "auto"
}
```
