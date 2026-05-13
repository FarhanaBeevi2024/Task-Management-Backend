# GitHub Actions + Render Deployment Setup Guide

## Setup Instructions

### Step 1: Prepare Your Repository
1. Commit these files to your repository:
   - `.github/workflows/deploy.yml`
   - `render.yaml`
   
2. Push to GitHub:
   ```bash
   git add .github/workflows/deploy.yml render.yaml
   git commit -m "Add GitHub Actions and Render deployment config"
   git push origin main
   ```

### Step 2: Create a Render Account
1. Go to [render.com](https://render.com)
2. Sign up and connect your GitHub account
3. Create a new Web Service:
   - Select "Deploy an existing GitHub repository"
   - Choose your Task-Management-Backend repository
   - Set the build command: `npm install`
   - Set the start command: `npm start`
   - Select the **Free** plan

### Step 3: Add Environment Variables in Render
1. In your Render service dashboard, go to **Environment** tab
2. Add all required environment variables from your `.env` file:
   - `SUPABASE_URL`
   - `SUPABASE_KEY`
   - `SUPABASE_SERVICE_ROLE_KEY`
   - Any other secrets your app needs

3. **Important**: Do NOT commit `.env` to GitHub. Add this to `.gitignore`:
   ```
   .env
   .env.local
   ```

### Step 4: Get Render Deployment Keys for GitHub Actions
1. Go to Render account settings → **API Keys**
2. Create a new API key (or use existing one)
3. Copy your **Service ID** from your service's dashboard URL:
   - URL pattern: `https://dashboard.render.com/services/srv-xxxxx...`
   - The `srv-xxxxx...` part is your RENDER_SERVICE_ID

### Step 5: Add GitHub Secrets
1. Go to your GitHub repository → **Settings** → **Secrets and variables** → **Actions**
2. Click **New repository secret** and add:
   
   | Secret Name | Value |
   |---|---|
   | `RENDER_SERVICE_ID` | `srv-xxxxxxxxx` (from Render dashboard) |
   | `RENDER_API_KEY` | Your Render API key |

### Step 6: Test the Pipeline
1. Make a change to your code and push to `main`:
   ```bash
   git commit --allow-empty -m "Test GitHub Actions"
   git push origin main
   ```
2. Watch the workflow:
   - Go to GitHub repo → **Actions** tab
   - See the workflow run in progress
   - Once complete, check Render dashboard for deployment status

## What the Workflow Does

- **On Pull Request**: Runs linting and tests (no deployment)
- **On Push to main**: Runs tests, then deploys to Render automatically
- **Manual Trigger**: Run workflow from Actions tab anytime

## Free Tier Limits

- **Render Free Plan**: 750 hours/month (covers 1 always-on service)
- **GitHub Actions**: 2,000 free minutes/month
- Services spin down after 15 minutes of inactivity (starts back up with first request)

## Troubleshooting

### Workflow fails to deploy
- Check GitHub Actions logs for error messages
- Verify `RENDER_SERVICE_ID` and `RENDER_API_KEY` are correct in secrets
- Ensure your service is linked to the correct GitHub repository in Render

### Application crashes on Render
- Check Render service logs in dashboard
- Verify all environment variables are set in Render (not in `.env`)
- Ensure `PORT` environment variable is set (Render uses dynamic ports)

### Environment variables not loading
- Do NOT use `.env` in production—set all vars in Render dashboard
- Render doesn't read local `.env` files automatically

## Next Steps

1. Test a deployment manually first (via Render dashboard)
2. Once working, push code changes to trigger automatic deployments
3. Monitor logs in Render dashboard for issues
4. Consider adding a Slack/Discord notification to workflow if needed
