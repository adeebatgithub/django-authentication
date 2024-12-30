class SessionSecurityMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Get session data
        session_ip = request.session.get('ip')
        session_ua = request.session.get('user_agent')

        # Get current request data
        current_ip = self.get_client_ip(request)
        current_ua = request.META.get('HTTP_USER_AGENT', '')

        # Validate session
        if session_ip and session_ip != current_ip:
            request.session.flush()  # Invalidate session
        elif session_ua and session_ua != current_ua:
            request.session.flush()

        # Update session
        request.session['ip'] = current_ip
        request.session['user_agent'] = current_ua

        return self.get_response(request)

    @staticmethod
    def get_client_ip(request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0]
        return request.META.get('REMOTE_ADDR')
