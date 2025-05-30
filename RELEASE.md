# 🚀 Release Guide for RustWall

This guide explains how to publish a new release of RustWall to crates.io using the automated GitHub Actions workflow.

## 📋 Prerequisites

Before you can publish releases, ensure you have:

1. **Crates.io Account**: Linked to your GitHub account
2. **API Token**: Set up in GitHub repository secrets
3. **Repository Access**: Push access to the main repository

## 🔑 One-Time Setup: Crates.io API Token

### Step 1: Get Your Crates.io API Token

1. Go to [crates.io](https://crates.io/)
2. Log in with your GitHub account
3. Navigate to **Account Settings** → **API Tokens**
4. Click **"New Token"**
5. Set permissions to **"Publish"**
6. Copy the generated token (you won't see it again!)

### Step 2: Add Token to GitHub Secrets

1. Go to your GitHub repository
2. Navigate to **Settings** → **Secrets and variables** → **Actions**
3. Click **"New repository secret"**
4. Name: `CARGO_REGISTRY_TOKEN`
5. Value: Paste your crates.io API token
6. Click **"Add secret"**

## 📦 Publishing a New Release

### Step 1: Prepare the Release

1. **Update the version** in `Cargo.toml`:
   ```toml
   [package]
   name = "rustwall"
   version = "0.2.0"  # ← Update this version number
   ```

2. **Update version references** in documentation if needed

3. **Test locally** to ensure everything works:
   ```bash
   cargo test --workspace --all-features
   cargo build --workspace --all-features
   cargo publish --dry-run
   ```

4. **Commit and push** the version change:
   ```bash
   git add Cargo.toml
   git commit -m "chore: bump version to v0.2.0"
   git push origin main
   ```

### Step 2: Create GitHub Release

1. **Go to your repository** on GitHub
2. **Click "Releases"** (in the right sidebar)
3. **Click "Create a new release"**
4. **Fill in the release details**:
   - **Tag version**: `v0.2.0` (must match Cargo.toml version with 'v' prefix)
   - **Release title**: `v0.2.0` or `RustWall v0.2.0`
   - **Description**: Add release notes (see template below)
5. **Click "Publish release"**

### Step 3: Automated Process

Once you publish the release, GitHub Actions will automatically:

✅ **Run Tests**: Full test suite across multiple platforms  
✅ **Quality Checks**: Code formatting and clippy lints  
✅ **Build Binaries**: Cross-platform release binaries  
✅ **Publish to Crates.io**: Automatic package publishing  
✅ **Attach Artifacts**: Binaries attached to GitHub release  

## 📝 Release Notes Template

Use this template for your release description:

```markdown
## 🚀 What's New in v0.2.0

### ✨ New Features
- Added new anonymity protection features
- Enhanced DDoS mitigation capabilities
- Improved Tor network integration

### 🛠️ Improvements
- Better error handling in CAPTCHA system
- Performance optimizations
- Updated dependencies

### 🐛 Bug Fixes
- Fixed issue with session timeout handling
- Resolved memory leak in traffic analysis

### 📚 Documentation
- Updated API documentation
- Added new usage examples
- Improved installation guide

### 🔧 Technical Changes
- Refactored module structure
- Added comprehensive test coverage
- Enhanced CI/CD pipeline

## 📦 Installation

```bash
cargo add rustwall
```

## 🔗 Links
- [Crates.io](https://crates.io/crates/rustwall)
- [Documentation](https://docs.rs/rustwall)
- [Changelog](CHANGELOG.md)
```

## 🔍 Monitoring the Release

### Check Release Progress

1. **GitHub Actions**: Go to **Actions** tab to monitor workflow progress
2. **Crates.io**: Check [crates.io/crates/rustwall](https://crates.io/crates/rustwall) for publication
3. **Release Assets**: Verify binaries are attached to the GitHub release

### If Something Goes Wrong

1. **Check workflow logs** in the Actions tab
2. **Common issues**:
   - Version already exists on crates.io
   - API token expired or invalid
   - Test failures
   - Build errors on specific platforms

## 📊 Version Numbering

Follow [Semantic Versioning](https://semver.org/):

- **MAJOR** (1.0.0): Breaking changes
- **MINOR** (0.1.0): New features, backward compatible
- **PATCH** (0.0.1): Bug fixes, backward compatible

### Examples:
- `0.1.0` → `0.1.1`: Bug fix
- `0.1.1` → `0.2.0`: New features
- `0.9.0` → `1.0.0`: First stable release

## 🎯 Release Checklist

Before creating a release:

- [ ] Version updated in `Cargo.toml`
- [ ] All tests pass locally
- [ ] Documentation is up to date
- [ ] CHANGELOG.md updated (if you have one)
- [ ] No uncommitted changes
- [ ] Main branch is up to date

After creating a release:

- [ ] GitHub Actions workflow completed successfully
- [ ] Package appears on crates.io
- [ ] Release binaries are attached
- [ ] Documentation updated on docs.rs

## 🆘 Troubleshooting

### Common Issues

**"Version already exists"**
- You've already published this version
- Increment the version number in Cargo.toml

**"Invalid token"**
- Check that CARGO_REGISTRY_TOKEN is set correctly
- Token may have expired - generate a new one

**"Tests failed"**
- Fix failing tests before releasing
- Check the Actions tab for detailed error logs

**"Build failed"**
- Check for platform-specific build issues
- Review compiler errors in workflow logs

### Getting Help

- Check [GitHub Issues](https://github.com/austinsonger/rustwall/issues)
- Review [Cargo documentation](https://doc.rust-lang.org/cargo/)
- Ask in [Rust community forums](https://users.rust-lang.org/)

---

🎉 **Happy releasing!** Your automated workflow makes publishing new versions of RustWall simple and reliable.
