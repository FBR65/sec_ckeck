FROM httpd:2.4.41-alpine

# Install vulnerable components
RUN apk add --no-cache \
    php7-apache2 \
    php7 \
    php7-mysqli \
    php7-json

# Check if www-data user exists, if not create it
RUN if ! getent group www-data; then addgroup -g 82 -S www-data; fi && \
    if ! getent passwd www-data; then adduser -u 82 -D -S -G www-data www-data; fi

# Copy vulnerable configuration
COPY httpd.conf /usr/local/apache2/conf/httpd.conf
COPY vulnerable-app/ /usr/local/apache2/htdocs/

# Create upload directory
RUN mkdir -p /tmp/uploads && chmod 777 /tmp/uploads

# Set permissions
RUN chmod -R 755 /usr/local/apache2/htdocs/
RUN chown -R www-data:www-data /usr/local/apache2/htdocs/

EXPOSE 80
