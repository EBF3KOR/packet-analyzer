# Use the official Python image as the base image
FROM python:3.9

# Set the working directory to the root of the project
WORKDIR /

# Copy the requirements file into the container
COPY requirements.txt .

# Install the Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application code into the container
COPY app.py .

# Expose the port that the Flask app will run on
EXPOSE 5000

# Set the command to run the Flask app
CMD ["python", "app.py"]