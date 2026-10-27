"""TLS context with Windows roots and bundled CA certificates."""
import ssl


def tls_context():
    import certifi
    context = ssl.create_default_context()
    # Add bundled CAs to the process-local Windows trust context.
    context.load_verify_locations(cafile=certifi.where())
    return context
