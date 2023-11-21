
# NetworkGPT Backend Development

This is the backend development repository for NetworkGPT, which utilizes FastAPI for efficient and scalable network command processing with ChatGPT API integration.

## Getting Started with Development

Follow these steps to set up your local development environment:

### Prerequisites
- Python

### Setup
1. **Clone the Repository:**
   ```bash
   git clone https://github.com/k4l1sh/network-gpt.git
   cd network-gpt/backend
   ```

2. **Install Dependencies:**
   - Ensure you have Python installed, it's better to install it in a virtual environment.
   - Install required Python packages:
     ```bash
     pip install -r requirements.txt
     ```

3. **Run the Application:**
   - Start the FastAPI application with Uvicorn:
     ```bash
     sudo uvicorn main:app --host 0.0.0.0 --port 8000 --workers 16
     ```
   - The backend service will be accessible on `http://localhost:8000`.

4. **Develop!**
   - Make changes to the backend code.
   - Restart the Uvicorn server to reflect changes.

## Contributing
Contributions to the NetworkGPT backend are welcome. Please read the main repository's contributing guidelines and submit your pull requests to the backend branch.
