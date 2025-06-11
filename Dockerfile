# Deliberately vulnerable Dockerfile for testing AI vulnerability analysis
# This image contains known vulnerabilities for demonstration purposes

# Using an older Ubuntu version with known vulnerabilities
FROM ubuntu:20.04

# Set environment variables (some insecure practices for testing)
ENV DEBIAN_FRONTEND=noninteractive
ENV SECRET_KEY=hardcoded-secret-key-123
ENV DATABASE_URL=mysql://admin:password@localhost/app

# Install packages without updating (to keep vulnerable versions)
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    git \
    python3 \
    python3-pip \
    nodejs \
    npm \
    openjdk-8-jdk \
    mysql-client \
    openssh-server \
    vim \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

# Install vulnerable Python packages
COPY requirements.txt /app/requirements.txt
RUN pip3 install --no-cache-dir -r /app/requirements.txt

# Install vulnerable Node.js packages
COPY package.json /app/package.json
WORKDIR /app
RUN npm install

# Create application directory and copy source
COPY . /app/
WORKDIR /app

# Set up a vulnerable service (running as root)
RUN chmod +x /app/start.sh
RUN echo 'root:vulnerable123' | chpasswd
RUN service ssh start

# Expose multiple ports (some unnecessary)
EXPOSE 22 80 443 3000 3306 5432 8080 8443

# Run as root (insecure)
USER root

# Start the application
CMD ["/app/start.sh"] 