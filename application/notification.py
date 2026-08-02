from plyer import notification

#notification.notify(
#    title="Notification Title",
#    message="This is the notification message",
#    app_name="My App",
#    timeout=10  # Duration in seconds
#)   


def send_notification(title, message, app_name="Mini-SIEM", timeout=10):
    """
    Send a desktop notification.

    Args:
        title (str): The title of the notification.
        message (str): The message content of the notification.
        app_name (str): The name of the application sending the notification.
        timeout (int): Duration in seconds for which the notification is displayed.
    """
    notification.notify(
        title=title,
        message=message,
        app_name=app_name,
        timeout=timeout
    ) # type: ignore