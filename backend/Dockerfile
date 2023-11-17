# Use a Python base image
FROM python:3.9

# Set the working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y nmap iputils-ping


# Copy the Python requirements file
COPY requirements.txt ./

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the code
COPY . .

# Command to run the application
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "16"]