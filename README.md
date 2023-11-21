# Network GPT

Run network commands in a web terminal-inspired interface powered by ChatGPT API.

This repository contains a custom ChatGPT application that performs network commands on your own machine.

<div align="center">
  <img src="https://i.imgur.com/BeZexC0.png" alt="NetworkGPT screen"/>
</div>

Use spoken language to run Nmap or other network tools and chat with the results.

<div align="center">
  <img src="https://i.imgur.com/VVQrhD8.png" alt="Nmap output"/>
</div>


## Introduction
Network GPT offers a chat-based network management tool leveraging ChatGPT API for intuitive command execution and interaction. It aims to simplify network tasks like scanning, packet capture, and IP management through conversational input and output.

## Features
- **Network Scanning:** Automated tools for scanning network devices and services.
- **Packet Capture:** Real-time packet analysis for network troubleshooting.
- **User Interface:** Intuitive frontend in a web terminal-inspired chat for interacting with the network tools.

## Prerequisites
- Docker Compose

## Setup
1. Ensure Docker and Docker Compose are installed on your system.
```bash
docker-compose --version
```
2. Clone the repository and navigate to the root directory.
```bash
git clone https://github.com/k4l1sh/network-gpt.git
cd network-gpt
```
3. Get your [OpenAI API key](https://platform.openai.com/api-keys) and put it in the `docker-compose.yml` file.
```yml
environment:
    - OPENAI_API_KEY=put_your_openai_api_key_here
```
4. Run docker-compose to build and start the containers.
```bash
docker-compose up
```
5. Now access Network GPT that is configured to be accessible in http://localhost.

## Contributing
Contributions to Network GPT are welcome. Follow the standard fork-branch-PR workflow for submitting contributions.

## Built With
NGINX, FastAPI, React, TailwindCSS, Docker, Nmap, Scapy and ChatGPT API

