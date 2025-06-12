FROM python:3.10-slim

# Install system dependencies needed for building Python packages
RUN apt-get update && apt-get install -y \
    curl \
    build-essential \
    gcc \
    libpq-dev \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Poetry
RUN curl -sSL https://install.python-poetry.org | python3 - \
    && ln -s /root/.local/bin/poetry /usr/local/bin/poetry


# Copy only poetry files first for dependency install
COPY pyproject.toml ./
# poetry.lock* ./

# Install dependencies (add --no-dev if for production)
RUN poetry install --no-root --no-interaction --no-ansi

# Copy the rest of the application code
COPY . .

# Expose port
EXPOSE 8000

# Run the app using Poetry to ensure environment is active
CMD ["poetry", "run", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]