FROM python:3.11-slim

WORKDIR /app

# Prevent CPU thread thrashing on Railway/cloud container vCPUs
ENV OMP_NUM_THREADS=1 \
    OPENBLAS_NUM_THREADS=1 \
    MKL_NUM_THREADS=1 \
    VECLIB_MAXIMUM_THREADS=1 \
    NUMEXPR_NUM_THREADS=1 \
    PYTHONUNBUFFERED=1

# Install system libraries needed for OpenCV & ONNX OCR
RUN apt-get update && apt-get install -y --no-install-recommends \
    libgl1 \
    libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Pre-download and cache RapidOCR ONNX models inside image with single-thread & no cls for ultra-fast startup
RUN python -c "import os; os.environ['OMP_NUM_THREADS']='1'; from rapidocr_onnxruntime import RapidOCR; import numpy as np; RapidOCR(use_cls=False, intra_op_num_threads=1, inter_op_num_threads=1, limit_side_len=720, limit_type='max')(np.zeros((100, 100, 3), dtype=np.uint8))"

# Copy application source code
COPY . .

# Expose port (Railway dynamically sets $PORT)
ENV PORT=8000
EXPOSE 8000

# Start FastAPI application with 1 worker to eliminate CPU context switching
CMD ["sh", "-c", "uvicorn app:app --host 0.0.0.0 --port ${PORT:-8000} --workers 1"]

