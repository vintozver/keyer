#~/usr/bin/env python3

import board
import busio
import gpiozero
import gpiozero.pins.pigpio
import http.server
import serial
import signal
import sys
import threading
import time

from adafruit_pn532.uart import PN532_UART
import adafruit_character_lcd.character_lcd_rgb_i2c as character_lcd

from . import dispatcher as _dispatcher


class HttpRequestHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        email = self.headers.get('X-Email')
        if email is not None:
            dispatcher_obj = self.server.dispatcher
            result, status = dispatcher_obj.action_personalize(email)
            if result:
                self.send_response(200)
            else:
                self.send_response(404)
            self.end_headers()
            self.wfile.write(status.encode("utf-8") + b"\n")
        else:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"email is missing\n")

    def do_DELETE(self):
        dispatcher_obj = self.server.dispatcher
        dispatcher_obj.action_depersonalize()
        self.send_response(202)
        self.end_headers()
        self.wfile.write(b"\n")

    def do_PATCH(self):
        email = self.headers.get('X-Email')
        if email is not None:
            dispatcher_obj = self.server.dispatcher
            dispatcher_obj.action_revoke(email)
            self.send_response(202)
            self.end_headers()
            self.wfile.write(b"\n")
        else:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"email is missing\n")


class HttpServer(http.server.HTTPServer):
    def __init__(self, dispatcher: _dispatcher.Dispatcher):
        super(HttpServer, self).__init__(('', 8080), HttpRequestHandler)
        self.dispatcher = dispatcher


def main():
    lcd_columns = 16
    lcd_rows = 2
    lcd = character_lcd.Character_LCD_RGB_I2C(busio.I2C(board.SCL, board.SDA), lcd_columns, lcd_rows)
    lcd.clear()
    lcd.color = (0, 0, 0)
    lcd.message = "INITIALIZING ...\nplease wait"
    time.sleep(2)

    gpio_factory = gpiozero.pins.pigpio.PiGPIOFactory()
    buzzer = gpiozero.TonalBuzzer("GPIO12", pin_factory=gpio_factory)
    relay = gpiozero.LED("GPIO17", pin_factory=gpio_factory)

    ser = serial.Serial('/dev/ttyS0', 115200, timeout=0.1)
    pn532 = PN532_UART(ser, debug=False)
    pn532.SAM_configuration()

    dispatcher_obj = _dispatcher.Dispatcher(lcd, pn532, buzzer, relay)
    http_srv = HttpServer(dispatcher_obj)
    def http_thread_worker():
        return http_srv.serve_forever()
    http_thread = threading.Thread(target=http_thread_worker, name="http")

    def signal_term(sig, frame):
        lcd.color = (0, 0, 0)
        lcd.message = "UNAVAILABLE     \nplease wait ... "
        dispatcher_obj.shutdown()
        http_srv.shutdown()
        http_thread.join()
        sys.exit(0)

    def signal_int(sig, frame):
        return signal_term(sig, frame)

    signal.signal(signal.SIGINT, signal_int)
    signal.signal(signal.SIGTERM, signal_term)

    http_thread.start()
    dispatcher_obj.loop()  # blocks forever, until signal is received


if __name__ == '__main__':
    main()

