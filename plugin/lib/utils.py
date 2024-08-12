import pyperclip


def copy_to_clipboard(text: str):
    """Copy to clipboard

    Args:
        text (str)
    """
    pyperclip.copy(text)
