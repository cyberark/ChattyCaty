import logging

# Constants
DEBUG = True


def setup_logger():
    # Create a custom logger
    logger = logging.getLogger()

    # Create handlers
    c_handler = logging.StreamHandler()
    f_handler = logging.FileHandler('file.log', mode="a+")
    debug_level = logging.INFO

    if DEBUG:
        debug_level = logging.DEBUG
    logger.setLevel(debug_level)
    c_handler.setLevel(debug_level)
    f_handler.setLevel(debug_level)

    # Create formatters and add it to handlers
    c_format = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    f_format = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    c_handler.setFormatter(c_format)
    f_handler.setFormatter(f_format)

    # Add handlers to the logger
    logger.addHandler(c_handler)
    logger.addHandler(f_handler)
