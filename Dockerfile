# Use NGINX base image
FROM nginx:alpine

# Remove default NGINX static assets
RUN rm -rf /usr/share/nginx/html/*

# Copy the built frontend files
COPY --from=networkgptfrontend:latest /app/build /usr/share/nginx/html

# Copy the NGINX configuration
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80