# PythonAnywhere Deployment (Free Tier)

This guide sets up the Market Fraud Detection System on PythonAnywhere (free tier).

## 1) Upload the Project
Use PythonAnywhere Files UI to upload the project folder, or clone from Git if the repo is available online.

Recommended structure on PythonAnywhere:
```
/home/ManoharSamoji/Market-Fraud-Detection-System(Web App)/Back-end
/home/ManoharSamoji/Market-Fraud-Detection-System(Web App)/Front-end
```

## 2) Create Virtual Environment + Install Dependencies
Open a Bash console on PythonAnywhere and run:
```bash
cd ~/Market-Fraud-Detection-System(Web App)/Back-end
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## 3) Configure the Web App
Go to **Web** tab ? **Add a new web app**:
- Manual configuration
- Python 3.10+ (or nearest available)

Set:
- **Working directory:**
  ```
  /home/ManoharSamoji/Market-Fraud-Detection-System(Web App)/Back-end
  ```

- **WSGI configuration file** (replace the default contents with):
```python
import sys

path = '/home/ManoharSamoji/Market-Fraud-Detection-System(Web App)/Back-end'
if path not in sys.path:
    sys.path.append(path)

from wsgi import app as application
```

## 4) Environment Variables
In **Web ? Environment variables**, add:
```
SECRET_KEY=your-strong-secret
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your_email@gmail.com
SMTP_PASS=your_app_password
SMTP_FROM=Market Fraud Detection <your_email@gmail.com>
ADMIN_EMAIL=your_email@gmail.com
```

## 5) Static Files (Optional)
If you want PythonAnywhere to serve static files directly (optional), set:
- **URL:** `/css` ? **Directory:** `/home/ManoharSamoji/Market-Fraud-Detection-System(Web App)/Front-end/css`
- **URL:** `/js` ? **Directory:** `/home/ManoharSamoji/Market-Fraud-Detection-System(Web App)/Front-end/js`
- **URL:** `/image` ? **Directory:** `/home/ManoharSamoji/Market-Fraud-Detection-System(Web App)/Front-end/image`
- **URL:** `/pages` ? **Directory:** `/home/ManoharSamoji/Market-Fraud-Detection-System(Web App)/Front-end/pages`

(Your Flask app already serves these, so this step is optional.)

## 6) Reload
Click **Reload** in the Web tab.

## 7) Smoke Test
Visit:
- `/login`
- `/dashboard` (after login)
- `/admin` (admin only)
- `/admin/users`

## Notes
- Free tier apps sleep when idle.
- Use an App Password for Gmail SMTP.
