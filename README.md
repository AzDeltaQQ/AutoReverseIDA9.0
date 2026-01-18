edit : this plugin needs PYQT5 i havent added it to the requirements.txt so if you get an error just pip install pyqt and should be GTG

# AutoReverse Plugin for IDA Pro 9.0

🤖 **AI-powered reverse engineering assistant using Google Gemini API**

AutoReverse is a comprehensive IDA Pro 9.0 plugin designed to accelerate reverse engineering workflows with AI assistance. Specifically tuned for **World of Warcraft 3.3.5a** binary analysis, but applicable to general x86 reverse engineering tasks.
<img width="1598" height="576" alt="AutoReverse" src="https://github.com/user-attachments/assets/a6b1a394-288f-4b5d-b552-200e1f99cc32" />

Note: Currently only coded for using free gemini tier. Model Gemini pro 2.5. eventually will add multi model support, paid tier, etc. Also currently only tested "Analyze Current Item" ,  will start working on other features soon TM.
## 🌟 Features

### 🧠 **AI-Powered Function Analysis**
- **Deep Context Analysis**: Gathers comprehensive function context including callers, called functions, disassembly, and pseudocode
- **WoW-Specific Insights**: Specialized prompts for World of Warcraft client analysis
- **Interactive Chat Interface**: Follow-up questions and iterative analysis
- **Token Management**: Smart context limits and rate limiting handling

### 📊 **Comprehensive Analysis**
- **Function Documentation**: Automatic purpose identification and parameter analysis
- **Data Structure Analysis**: Smart structure recognition and creation
- **Cross-Reference Analysis**: Complete XREFs TO/FROM analysis with context
- **Calling Convention Detection**: Automatic identification of calling patterns

### 🔧 **Code Enhancement Tools**
- **Variable Renaming**: AI-suggested meaningful variable names
- **Type Setting**: Automatic function signature generation
- **Structure Creation**: Data structure analysis and IDA integration
- **Copy-Paste Ready**: Type declarations ready for IDA Pro

### 🎨 **Modern User Interface**
- **Rich Chat Interface**: HTML-formatted responses with syntax highlighting
- **Multiline Input**: Markdown support with Shift+Enter for new lines
- **Progress Tracking**: Real-time analysis progress and token counting
- **Error Handling**: Comprehensive error messages with suggestions

## 📦 Installation

### Option 1: Automatic Installation (Recommended)
```bash
# Download the repository
git clone https://github.com/AzDeltaQQ/AutoReverseIDA9.0.git

# Run the Windows installer
cd AutoReverseIDA9.0
python AutoReverse/install_windows.py
```

### Option 2: Manual Installation
1. Copy files to your IDA Pro plugins directory:
   ```
   C:\Program Files\IDA Professional 9.0\plugins\
   ├── auto_reverse.py                    # This file must go in plugins folder by itself.
   └── AutoReverse/                       #  This Folder must be in plugins folder .
       ├── modules/
       │   ├── config_manager.py
       │   ├── context_gatherer.py
       │   ├── gemini_client.py
       │   ├── struct_analyzer.py
       │   ├── type_setter.py
       │   ├── ui_manager.py
       │   └── variable_renamer.py
       ├── install_windows.py
       ├── README.md
       ├── LICENSE
       └── requirements.txt
   ```

2. Install dependencies:
   ```bash
   pip install -r AutoReverse/requirements.txt
   ```

## 🔑 Configuration

### Get Google Gemini API Key
1. Visit [Google AI Studio](https://makersuite.google.com/app/apikey)
2. Create a new API key
3. Copy the key for plugin configuration

### Setup in IDA Pro
1. Start IDA Pro 9.0
2. Open any binary file
3. Go to **Edit > AutoReverse > Configure API Key**
4. Paste your Gemini API key
5. **Edit > AutoReverse > Settings** to configure preferences

## 🚀 Usage

### Function Analysis
```
1. Position cursor in any function
2. Edit > AutoReverse > Analyze Current Item
3. Get comprehensive AI analysis with:
   - Function purpose and WoW context
   - Parameter analysis and calling convention
   - Cross-reference analysis
   - Copy-pastable type declaration
```

### Interactive Chat
- Ask follow-up questions about the analysis
- Request specific insights or clarifications
- Get code suggestions and improvements
- **Shift+Enter** for multiline input

### Data Analysis
```
1. Position cursor on data/offset/pointer
2. Edit > AutoReverse > Analyze Current Item
3. Get detailed data structure analysis
```

### Settings & Customization
```
Edit > AutoReverse > Settings
- Toggle prompt display in chat
- View current model settings
- Context limit information
```

## 🎯 World of Warcraft 3.3.5a Specialization

### Optimized for WoW Client Analysis
- **FrameScript System**: Lua-to-C++ bridge analysis
- **Game Object Recognition**: Player, NPC, item structures
- **Network Protocol**: Packet handling and opcodes
- **UI System**: WoW's custom UI framework analysis
- **Memory Management**: Custom allocators and object pools

### Example Analysis Output
```
Function: FrameScript_SerializeStringOrNil
Purpose: Pushes string or nil value onto Lua stack for UI scripting
Parameters: lua_State* L, const char* str
Context: FrameScript system for WoW UI addon communication

Type Declaration:
void FrameScript_SerializeStringOrNil(lua_State* L, const char* str);
```

## 🛠️ Technical Details

### System Requirements
- **IDA Pro 9.0** with Python support
- **Windows** (installer supports Windows, manual install for other OS)
- **Python 3.8+**
- **Google Gemini API** access

### API Integration
- **Google Gemini 2.5 Pro**: 2M token context window
- **Rate Limiting**: Smart handling with helpful error messages
- **Context Optimization**: Automatic truncation for API efficiency
- **Safety Settings**: BLOCK_NONE for technical content

### Performance Optimizations
- **Context Limits**: 
  - Max 8 callers per function (reduced from 10)
  - 80 lines disassembly (reduced from 100)
  - 40 lines per caller (reduced from 50)
- **Token Estimation**: Improved accuracy accounting for system prompts
- **Parallel Processing**: Async analysis with progress tracking

## 🧪 Example Workflows

### Basic Function Analysis
```python
# 1. Open WoW 3.3.5a client in IDA Pro
# 2. Navigate to any function (e.g., spell casting, movement)
# 3. Use AutoReverse to get AI analysis
# 4. Get instant insights about game mechanics
```

### Advanced Structure Analysis
```python
# 1. Find data structures (player object, item data, etc.)
# 2. Analyze with AutoReverse
# 3. Get IDA structure definitions
# 4. Apply to improve analysis accuracy
```

### Interactive Research
```python
# 1. Analyze complex function
# 2. Ask follow-up questions in chat:
#    - "How does this relate to spell casting?"
#    - "What WoW systems use this function?"
#    - "Can you explain the network protocol here?"
```

## 🔧 Development & Contribution

### Module Structure
```
AutoReverse/modules/
├── config_manager.py      # Settings and API key management
├── context_gatherer.py    # Function analysis and context collection
├── gemini_client.py       # Google Gemini API integration
├── struct_analyzer.py     # Structure analysis and creation
├── type_setter.py         # Type setting functionality
├── ui_manager.py          # User interface management
└── variable_renamer.py    # Variable renaming suggestions
```

### Key Features in Code
- **Error Handling**: Comprehensive try-catch with detailed logging
- **Context Gathering**: Smart XREFs analysis with external function filtering
- **UI Components**: PyQt5 integration with HTML rendering
- **API Management**: Rate limiting, token counting, and fallback handling

## 🐛 Troubleshooting

### Common Issues

**Plugin Not Loading**
```
- Check IDA Pro 9.0 Python support
- Verify all files in correct locations
- Check Output window for detailed errors
```

**API Errors**
```
- Verify Gemini API key is correct
- Check internet connectivity
- Monitor token usage (free tier: 250k/minute)
```

**Performance Issues**
```
- Large functions may hit rate limits
- Use Settings to adjust context limits
- Analyze smaller functions first
```

### Rate Limiting Solutions
- **Free Tier**: 15 RPM, 250k tokens/minute
- **Paid Tier**: Higher limits available
- **Context Optimization**: Plugin automatically manages context size
- **Error Recovery**: Helpful suggestions for limit exceeded errors

## 📄 License

MIT License - see [LICENSE](AutoReverse/LICENSE) for details.

## 🤝 Contributing

1. Fork the repository
2. Create feature branch: `git checkout -b feature-name`
3. Commit changes: `git commit -am 'Add feature'`
4. Push to branch: `git push origin feature-name`
5. Submit pull request

## 📞 Support

- **GitHub Issues**: Report bugs and request features
- **Documentation**: Check AutoReverse/README.md for detailed usage
- **IDA Output Window**: Enable debug logging for troubleshooting

## 🏆 Acknowledgments

- **Google Gemini**: AI analysis capabilities
- **IDA Pro**: Reverse engineering platform
- **Hex-Rays**: Decompiler integration
- **WoW Community**: Reverse engineering insights

---

**AutoReverse Plugin** - Accelerating reverse engineering with AI assistance 🚀
