# Usamos una imagen oficial de PHP con Apache
FROM php:8.2-apache

# Copiamos tus archivos al servidor
COPY . /var/www/html/

# Le decimos a Apache que escuche en el puerto correcto de Render
RUN sed -i 's/80/${PORT}/g' /etc/apache2/sites-available/000-default.conf /etc/apache2/ports.conf

# Configuramos permisos (importante para que no de Error 500)
RUN chown -R www-data:www-data /var/www/html
RUN a2enmod rewrite
