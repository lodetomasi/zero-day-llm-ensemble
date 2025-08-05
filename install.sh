#!/bin/bash
# Install zeroday command

echo "🚀 Installing Zero-Day Detection CLI..."

# Get the directory of this script
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Create a wrapper script
cat > /tmp/zeroday << EOF
#!/bin/bash
python3 "$DIR/zeroday.py" "\$@"
EOF

# Make it executable
chmod +x /tmp/zeroday

# Try to install in /usr/local/bin (may require sudo)
if [ -w /usr/local/bin ]; then
    mv /tmp/zeroday /usr/local/bin/
    echo "✅ Installed! You can now use: zeroday CVE-2024-3400"
else
    echo "⚠️  Need sudo to install globally. Run:"
    echo "   sudo mv /tmp/zeroday /usr/local/bin/"
    echo ""
    echo "Or use directly with:"
    echo "   ./zeroday.py CVE-2024-3400"
fi