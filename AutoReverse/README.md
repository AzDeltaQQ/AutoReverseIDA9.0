# AutoReverse Plugin

AI-powered reverse engineering assistant for IDA Pro 9.0 using Google Gemini.

## Features

- **Function Analysis**: Analyze decompiled functions and get AI-powered insights
- **Structure Analysis**: Automatically analyze and create data structures
- **Variable Renaming**: Get intelligent variable name suggestions
- **Type Setting**: Automatically set function and variable types
- **AI-Powered Insights**: Leverage Google Gemini for reverse engineering assistance

## Installation

### Automatic Installation (Recommended)

1. Download or clone the plugin files
2. Run the installer:
   ```bash
   python install_windows.py
   ```
3. Follow the installation prompts

### Manual Installation

1. Copy the `AutoReverse` directory to your IDA Pro plugins directory:
   - Windows: `C:\Program Files\IDA Professional 9.0\plugins\AutoReverse\`
   - Ensure the directory structure looks like:
     ```
     plugins/AutoReverse/
     ├── auto_reverse.py
     ├── modules/
     │   ├── __init__.py
     │   ├── config_manager.py
     │   ├── gemini_client.py
     │   ├── struct_analyzer.py
     │   ├── type_setter.py
     │   ├── ui_manager.py
     │   └── variable_renamer.py
     ├── README.md
     ├── LICENSE
     └── requirements.txt
     ```

2. Install required Python packages:
   ```bash
   pip install -r requirements.txt
   ```

## Configuration

1. Start IDA Pro 9.0
2. Open any binary file
3. Look for "AutoReverse" in the Edit menu
4. Select "Configure API Key"
5. Enter your Google Gemini API key

### Getting a Gemini API Key

1. Go to [Google AI Studio](https://makersuite.google.com/app/apikey)
2. Create a new API key
3. Copy the key and paste it into the plugin configuration

## Usage

### Function Analysis

1. Position your cursor in a function
2. Go to Edit > AutoReverse > Analyze Function
3. The plugin will analyze the function and provide insights

### Structure Analysis

1. Position your cursor on data you want to analyze
2. Go to Edit > AutoReverse > Analyze Structure
3. The plugin will create a structure and provide analysis

### Variable Renaming

1. Position your cursor in a function
2. Go to Edit > AutoReverse > Rename Variables
3. The plugin will suggest better variable names

### Type Setting

1. Position your cursor in a function
2. Go to Edit > AutoReverse > Set Function Type
3. The plugin will analyze and set appropriate types

## Troubleshooting

### Plugin Not Loading

1. Check that all files are in the correct location
2. Ensure you have Python support in IDA Pro
3. Check the Output window for error messages

### API Connection Issues

1. Verify your API key is correct
2. Check your internet connection
3. Ensure you have the required Python packages installed
4. Test connection in the plugin settings

### Common Issues

- **No menu items appearing**: Check file permissions and ensure all files are in the correct location
- **Import errors**: Make sure all module files are in the `modules/` directory
- **API errors**: Verify your API key and network connectivity

## Requirements

- IDA Pro 9.0 with Python support
- Python 3.8+
- Google Gemini API key
- Required Python packages (see requirements.txt)

## License

MIT License - see LICENSE file for details.

## Support

For issues and questions:
1. Check the troubleshooting section
2. Enable debug logging in the plugin
3. Check IDA Pro's Output window for error messages
4. Create an issue with detailed information

## Changelog

### Version 1.0.0
- Initial release
- Function analysis with Google Gemini
- Structure analysis and creation
- Variable renaming suggestions
- Type setting functionality
- IDA Pro 9.0 compatibility 