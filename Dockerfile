FROM python:3.10-bullseye
LABEL authors="Andika"
WORKDIR /app
COPY . .
RUN pip install -r requirements.txt
CMD ["python", "main.py"]