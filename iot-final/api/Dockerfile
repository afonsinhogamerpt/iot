FROM python 
RUN pip install flask && pip install flask-mysqldb
RUN pip install bcrypt
RUN pip install flask_cors
RUN pip install flask_mqtt
COPY teste.py teste.py 
CMD ["python3", "teste.py"]
