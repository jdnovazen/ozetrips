## Use an official Python runtime as a parent image
FROM python:3.9

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Set the working directory in the container
WORKDIR /code

# Install Gunicorn and any other dependencies
RUN pip install gunicorn

# Copy the requirements file into the container at /code
COPY requirements.txt /code/

# Install the dependencies
RUN pip install -r requirements.txt
# Install waitress
RUN pip install waitress

# Copy the current directory contents into the container at /code
COPY . /code

# Expose the port Gunicorn will listen on
EXPOSE 8000

# Command to run Gunicorn when the container starts
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "OzeTrips.wsgi:application"]
