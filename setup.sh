#!/bin/bash
# Zero-Day Detection System - Quick Setup Script

echo "🚀 Zero-Day Detection System Setup"
echo "=================================="
echo ""

# Check Python version
echo "📍 Checking Python version..."
python_version=$(python3 --version 2>&1 | awk '{print $2}')
required_version="3.8"

if [ "$(printf '%s\n' "$required_version" "$python_version" | sort -V | head -n1)" = "$required_version" ]; then 
    echo "✅ Python $python_version (OK)"
else
    echo "❌ Python $python_version is too old. Need 3.8+"
    exit 1
fi

# Create virtual environment
echo ""
echo "📍 Creating virtual environment..."
if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo "✅ Virtual environment created"
else
    echo "✅ Virtual environment already exists"
fi

# Activate virtual environment
echo ""
echo "📍 Activating virtual environment..."
source venv/bin/activate

# Install dependencies
echo ""
echo "📍 Installing dependencies..."
pip install -r requirements.txt --quiet
echo "✅ Dependencies installed"

# Create necessary directories
echo ""
echo "📍 Creating directories..."
mkdir -p data cache logs reports detection_reports
echo "✅ Directories created"

# Check for API key
echo ""
echo "📍 Checking API key..."
if [ -z "$OPENROUTER_API_KEY" ]; then
    echo "⚠️  No API key found!"
    echo ""
    echo "To set your API key:"
    echo "export OPENROUTER_API_KEY='your-api-key-here'"
    echo ""
    echo "Get your key from: https://openrouter.ai/"
else
    echo "✅ API key found"
fi

# Download initial dataset
echo ""
echo "📍 Preparing initial dataset..."
if [ ! -f "data/verified_dataset.json" ]; then
    echo "Downloading dataset..."
    python3 scripts/balance_dataset.py 100 2>/dev/null
    echo "✅ Initial dataset ready"
else
    echo "✅ Dataset already exists"
fi

# Test the system
echo ""
echo "📍 Testing system..."
python3 zero_day_detector.py status

echo ""
echo "=================================="
echo "✅ Setup complete!"
echo ""
echo "Next steps:"
echo "1. Set your API key (if not done):"
echo "   export OPENROUTER_API_KEY='your-key'"
echo ""
echo "2. Try your first detection:"
echo "   python zero_day_detector.py detect CVE-2024-3400"
echo ""
echo "3. Run a quick test:"
echo "   python zero_day_detector.py test --zero-days 2 --regular 2"
echo ""
echo "Happy detecting! 🎯"