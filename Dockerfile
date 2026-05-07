# HeapTruffle v3 — AI-Assisted Browser Memory Forensics Platform
FROM node:18-bullseye

# Install Google Chrome stable
RUN apt-get update \
    && apt-get install -y wget gnupg \
    && wget -q -O - https://dl-ssl.google.com/linux/linux_signing_key.pub | apt-key add - \
    && sh -c 'echo "deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main" >> /etc/apt/sources.list.d/google.list' \
    && apt-get update \
    && apt-get install -y google-chrome-stable fonts-ipafont-gothic fonts-wqy-zenhei fonts-thai-tlwg fonts-kacst fonts-freefont-ttf libxss1 \
      --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy package files first for better layer caching
COPY package*.json ./

# Install dependencies
RUN npm install --omit=dev

# Copy source files
COPY server.js ./
COPY src/ ./src/
COPY public/ ./public/

# Create data directory for SQLite database
RUN mkdir -p /app/data

# Fix #18: Do NOT copy .env.example as .env — secrets must be injected at runtime.
# Required environment variables (pass with -e or --env-file):
#   JWT_SECRET=<long-random-string>   (REQUIRED)
#   GEMINI_API_KEY=<your-key>         (optional, enables AI reports)
#   PORT=3000                         (optional, default 3000)
#   NODE_ENV=production               (recommended)
#   CORS_ORIGIN=https://yourdomain.com (recommended in production)

EXPOSE 3000

# Use non-root user for security
RUN groupadd -r heaptruffle && useradd -r -g heaptruffle -G audio,video heaptruffle \
    && chown -R heaptruffle:heaptruffle /app
USER heaptruffle

ENTRYPOINT ["node", "server.js"]

