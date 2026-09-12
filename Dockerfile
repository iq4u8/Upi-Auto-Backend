FROM python:3.11-slim

WORKDIR /app

# Install system libraries needed for OpenCV & ONNX OCR
RUN apt-get update && apt-get install -y --no-install-recommends \
    libgl1 \
    libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Pre-download and cache all RapidOCR ONNX models inside image for instant zero-latency processing
RUN python -c "from rapidocr_onnxruntime import RapidOCR; import numpy as np; RapidOCR()(np.zeros((100, 100, 3), dtype=np.uint8))"

# Copy application source code
COPY . .

# Expose port (Railway dynamically sets $PORT)
ENV PORT=8000
EXPOSE 8000

# Start FastAPI application
CMD ["sh", "-c", "uvicorn app:app --host 0.0.0.0 --port ${PORT:-8000}"]
