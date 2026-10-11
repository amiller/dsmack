FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements-dstack.txt /app/requirements-dstack.txt
RUN pip install --no-cache-dir -r /app/requirements-dstack.txt
COPY *.py /app/experiments/coupon_redemption/
ENTRYPOINT ["python", "-m", "experiments.coupon_redemption.runner"]
CMD ["--help"]
