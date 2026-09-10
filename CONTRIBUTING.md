# Contributing to Eye 🛡️

Thank you for your interest in contributing to **Eye**! We welcome contributions to improve our real-time SOC monitoring, threat detection rules, AI copilot capabilities, and UI/UX.

---

## 📋 Code of Conduct

We are committed to providing a welcoming, inclusive, and harassment-free environment for all contributors. Please be respectful, constructive, and collaborative.

---

## 🛠️ Development Workflow

### 1. Prerequisites
- **Node.js**: v18.0.0+ or v20.0.0+ LTS
- **MongoDB**: v6.0+ or v7.0+ (running locally on port `27017` or via Docker)
- **Git**: Latest version

### 2. Fork and Clone
```bash
git clone https://github.com/agr1m5/log-sage.git
cd log-sage
```

### 3. Installation & Setup
Install all dependencies across the monorepo:
```bash
npm install
```

Copy the example environment configurations:
```bash
cp server/.env.example server/.env
cp agent/.env.example agent/.env
```

### 4. Running the Development Environment
```bash
# Start Client and Server concurrently
npm run dev

# Start Endpoint Agent (in another terminal)
npm run agent
```

---

## 🌿 Branching & Commit Guidelines

- **Branch Naming**:
  - `feat/<feature-name>` for new features
  - `fix/<bug-description>` for bug fixes
  - `docs/<documentation-change>` for documentation updates
  - `refactor/<module-name>` for code refactoring

- **Commit Messages**:
  Follow Conventional Commits:
  - `feat(detection): add reverse shell signature rule`
  - `fix(socket): resolve reconnection listener leak`
  - `docs(readme): add Docker Compose troubleshooting steps`
  - `style(client): improve severity badge contrast`

---

## 🧪 Testing & Verification

Before submitting a Pull Request, ensure that:
1. The client builds without errors:
   ```bash
   npm run build --workspace=client
   ```
2. The server boots cleanly and connects to MongoDB.
3. No secrets, API keys, or `.env` files are tracked in git.

---

## 🔒 Security Vulnerability Reporting

If you discover a security vulnerability in Eye, please do **NOT** open a public issue. Instead, disclose it responsibly by contacting the maintainers or emailing the security contact specified in the repository.

---

## 📜 Pull Request Process

1. Ensure your code conforms to the existing architecture and directory patterns.
2. Update relevant documentation (`README.md`, sub-package docs) if adding new configuration parameters or endpoints.
3. Open a Pull Request against the `main` branch with a clear description of the changes and testing steps.
4. Maintainers will review your PR and provide feedback.
