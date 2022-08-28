import asyncio
import aioprocessing
import sys
import os
import json
import ssl
import socket
import gc
import psutil
import traceback
import random
import hashlib
import time
import datetime
import ipaddress


class pgl_base:
    @staticmethod
    async def clean_up(writer1=None, writer2=None):
        try:
            if writer1 != None:
                writer1.close()
        except BaseException as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None
        try:
            if writer2 != None:
                writer2.close()
        except BaseException as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None
        try:
            if writer1 != None:
                await writer1.wait_closed()
        except BaseException as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None
        try:
            if writer2 != None:
                await writer2.wait_closed()
        except BaseException as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None

    @staticmethod
    def set_priority(level: str):
        if not isinstance(level, str):
            level = str(level)
        p = psutil.Process(os.getpid())
        if level.lower() == 'real_time':
            p.nice(psutil.REALTIME_PRIORITY_CLASS)
        elif level.lower() == 'high':
            p.nice(psutil.HIGH_PRIORITY_CLASS)
        elif level.lower() == 'above_normal':
            p.nice(psutil.ABOVE_NORMAL_PRIORITY_CLASS)
        elif level.lower() == 'normal':
            p.nice(psutil.NORMAL_PRIORITY_CLASS)
        elif level.lower() == 'below_normal':
            p.nice(psutil.BELOW_NORMAL_PRIORITY_CLASS)
        elif level.lower() == 'idle':
            p.nice(psutil.IDLE_PRIORITY_CLASS)
        else:
            raise Exception('Unexpected value')

    @staticmethod
    def calculate_ports(uuid: bytes | str, offset_day: int = 0):
        if isinstance(uuid, str):
            uuid = uuid.encode('utf-8')
        port_list = []
        for x in range(10):
            t = uuid + str(datetime.datetime.utcfromtimestamp(time.time() + (x + offset_day) * 86400))[:10].encode('utf-8')
            t = hashlib.sha256(t).digest()
            port_list.append((int.from_bytes(t, byteorder='little', signed=False) % 65535 + 1025))
        return port_list

    @staticmethod
    def translate(content: str):
        return content.replace('\\', '/')

    def get_listener(self, port: int, local=True):
        if not isinstance(port, int):
            port = int(port)
        if local:
            address = (self.config['localhost_ip'], port)
        else:
            address = (self.config['remote_ip'], port)
        if self.config['has_ipv6']:
            listener = socket.create_server(address=address, family=socket.AF_INET6, dualstack_ipv6=True, backlog=2048)
        else:
            listener = socket.create_server(address=address, family=socket.AF_INET, dualstack_ipv6=False, backlog=2048)
        return listener

    def create_server_stream(self, port: int, handler, local=True, context=None):
        listener = self.get_listener(port, local)
        if not context:
            return asyncio.start_server(client_connected_cb=handler, sock=listener, backlog=2048)
        else:
            return asyncio.start_server(client_connected_cb=handler, sock=listener, backlog=2048, ssl=context)

    @staticmethod
    def find_available_port(port_list: list = None, exception: list = None, num: int = 1):
        def connect():
            sock = None
            valid_port = []
            for port in port_list:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.5)
                    sock.connect(('127.0.0.1', port))
                    sock.close()
                    sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                    sock.settimeout(0.5)
                    sock.connect(('::1', port))
                    sock.close()
                except Exception as error:
                    traceback.clear_frames(error.__traceback__)
                    error.__traceback__ = None
                    sock.close()
                    if str(error) == 'timed out' and port not in exception:
                        valid_port.append(port)
                    if len(valid_port) >= num:
                        return valid_port

        while True:
            if not port_list:
                port_list = [random.randint(1024, 65535)]
            if not exception:
                exception = []
            port = connect()
            if port:
                return port


class pgl_ssl_context:
    def get_proxy_context(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.set_alpn_protocols(['http/1.1'])
        context.load_cert_chain(self.config['cert'], self.config['key'])
        return context

    @staticmethod
    def get_normal_context():
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.set_alpn_protocols(['http/1.1'])
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True
        context.load_default_certs()
        return context


class pgl_connect(pgl_ssl_context):
    async def open_connection(self, address, TLS=False, server_hostname=None, ssl_handshake_timeout=5, timeout=5, retry=1, context=None):
        for x in range(retry):
            try:
                if TLS:
                    if context is None:
                        context = self.get_normal_context()
                    if server_hostname is None:
                        server_hostname = address[0]
                    return await asyncio.wait_for(asyncio.open_connection(host=address[0],
                                                                          port=address[1],
                                                                          ssl=context,
                                                                          server_hostname=server_hostname,
                                                                          ssl_handshake_timeout=ssl_handshake_timeout),timeout)
                else:
                    return await asyncio.wait_for(asyncio.open_connection(host=address[0],
                                                                          port=address[1]), timeout)
            except Exception as error:
                traceback.clear_frames(error.__traceback__)
                error.__traceback__ = None
        raise Exception('Too many attempts')


class pangolin_controller(pgl_base, pgl_ssl_context):
    def __int__(self, config):
        super().__init__()
        self.init(config)

    def init(self, config):
        gc.set_threshold(100000, 50, 50)
        self.pool = dict()
        self.protocol_table = dict()
        self.persist_binding = dict()
        self.config = config
        self.set_priority('above_normal')
        self.create_loop()

    def create_loop(self):
        self.loop = asyncio.new_event_loop()
        self.loop.set_exception_handler(self.exception_handler)
        self.loop.create_server(self.create_server_stream(self.config['localhost_port']['controller'][0], self.handler_for_localhost))
        self.loop.create_server(self.create_server_stream(self.config['remote_port']['controller'][0], self.handler_for_remote, self.get_proxy_context()))
        self.loop.run_forever()

    async def handler_for_localhost(self, client_reader, client_writer):
        try:
            UUID = await asyncio.wait_for(client_reader.read(36), 10)
            if UUID == b"31a8e78e-af98-40ed-ba08-7471b444fe40":
                await self.for_core(client_reader, client_writer)
            elif UUID == b"82b28d69-e47f-4a25-a700-84eba7c2a80d":
                await self.for_balancer(client_reader, client_writer)
            else:
                raise Exception("Unauthorized Access")
        except Exception as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None
            await self.clean_up(client_writer)

    async def for_core(self, client_reader, client_writer):
        while True:
            data = await client_reader.read(4096)
            ID, future_pool = data.split(b"\n")
            future_pool = json.loads(future_pool)
            for x in future_pool.keys():
                future_pool[x] = len(future_pool[x])
            self.pool[int(ID)] = future_pool

    async def for_balancer(self, client_reader, client_writer):
        while True:
            IP, port = (await client_reader.read(4096)).split(b"\n")
            available_servers = list(self.protocol_table[self.config['port2service'][int(port)]])
            TCP_Inventory_Total = 0
            for x in self.pool.values():
                for y in available_servers:
                    if y in self.pool[x]:
                        TCP_Inventory_Total += self.pool[x][y]
            if TCP_Inventory_Total <= 0:
                client_writer.write(b"None")
                await client_writer.drain()
                continue
            elif IP not in self.persist_binding or self.persist_binding[IP] not in available_servers:
                server = available_servers[random.randint(0, len(available_servers) - 1)]
                self.persist_binding[IP] = server
            while True:
                ID = random.randint(0, len(self.pool) - 1)
                if self.persist_binding[IP] in self.pool[ID] and self.pool[ID][self.persist_binding[IP]] > 0:
                    client_writer.write(str(ID).encode('utf-8') + b"\n" + self.persist_binding[IP].encode('utf-8'))
                    await client_writer.drain()
                    break

    async def handler_for_remote(self, client_reader, client_writer):
        try:
            UUID = await asyncio.wait_for(client_reader.read(36), 10)
            if UUID not in self.config['keys']:
                raise Exception("Unauthorized Access")
            _sock = client_writer.get_extra_info('socket')
            remote_server_ip = _sock.getpeername()[0]  # 远程服务器IP
            supported_protocol = (await asyncio.wait_for(client_reader.read(4096), 10)).split(b"\n")
            for x in supported_protocol:
                key = x.decode('utf-8')
                key = key.lower()
                if key in self.protocol_table:
                    self.protocol_table[key].add(remote_server_ip)
                else:
                    self.protocol_table[key] = {remote_server_ip}
            TCP_Inventory_Total = 0
            while True:
                for x in self.pool.values():
                    if remote_server_ip in self.pool[x]:
                        TCP_Inventory_Total += self.pool[x][remote_server_ip]
                if TCP_Inventory_Total < int(self.config['TCP_pool_size']):
                    client_writer.write(str(int(self.config['TCP_pool_size']) - TCP_Inventory_Total).encode('utf-8'))
                    await client_writer.drain()
                await asyncio.sleep(1)
        except Exception as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None
            await self.clean_up(client_writer)

    def exception_handler(self, loop, context):
        pass


class pangolin_core(pgl_base, pgl_connect):
    def __int__(self, config, ID):
        super().__init__()
        self.init(config, ID)

    def init(self, config, ID):
        gc.set_threshold(100000, 50, 50)
        self.config = config
        self.ID = ID
        self.geoip_list = self.config['geoip_list']
        self.future_pool = dict()
        self.set_priority('above_normal')
        self.create_loop()

    def create_loop(self):
        self.loop = asyncio.new_event_loop()
        self.loop.set_exception_handler(self.exception_handler)
        for x in self.config['remote_port']['core']:
            self.loop.create_task(self.create_server_stream(x, self.handler, False, self.get_proxy_context()))
        self.loop.create_task(self.controller_com())
        self.loop.create_task(self.create_server_sock())
        self.loop.run_forever()

    async def create_server_sock(self):
        while True:
            sock = None
            try:
                sock, remote_server_ip = await self.config['pipes_sock'][self.ID][0].coro_recv()
                foreign_user_ip = sock.getpeername()[0]  # 海外用户IP
                local_service_port = sock.getsockname()[1]  # 本地服务端口
                if self.is_china_ip(foreign_user_ip):
                    raise Exception("Unauthorized Access")
                future = self.future_pool[remote_server_ip].pop()
                future.set_result((sock, self.config['port2port'][local_service_port]))
            except Exception as error:
                traceback.clear_frames(error.__traceback__)
                error.__traceback__ = None
                await self.clean_up(sock)

    async def handler(self, client_reader, client_writer):
        try:
            UUID = await asyncio.wait_for(client_reader.read(36), 10)
            if UUID not in self.config['keys']:
                raise Exception("Unauthorized Access")
            _sock = client_writer.get_extra_info('socket')
            remote_server_ip = _sock.getpeername()[0]  # 远程服务器IP
            while True:
                future = self.loop.create_future()
                if remote_server_ip in self.future_pool:
                    self.future_pool[remote_server_ip].add(future)
                else:
                    self.future_pool[remote_server_ip] = {future}
                sock, sendto = await future
                if sock is None:
                    client_writer.write(b"OK")
                    await client_writer.drain()
                else:
                    client_writer.write(b"\n\n" + int.to_bytes(sendto, 2, byteorder='little', signed=False))
                    await client_writer.drain()
                    done, pending = await asyncio.wait(await self.make_switches(sock, client_reader, client_writer), return_when=asyncio.FIRST_COMPLETED)
                    for x in pending:
                        x.cancel()
                    break
        except Exception as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None
            await self.clean_up(client_writer)

    async def pool_health_manager(self):
        pass

    async def make_switches(self, sock, sr, sw):
        return [asyncio.create_task(self.switch_up(sock, sw)), asyncio.create_task(self.switch_down(sr, sock))]

    async def switch_down(self, reader, writer):
        try:
            while True:
                data = await reader.read(65535)
                if data == b"":
                    raise Exception
                await self.loop.sock_sendall(writer, data)
        except BaseException as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None
        finally:
            await self.clean_up(writer)

    async def switch_up(self, reader, writer):
        try:
            while True:
                data = await self.loop.sock_recv(reader, 65535)
                if data == b"":
                    raise Exception
                writer.write(data)
                await writer.drain()
        except BaseException as error:
            traceback.clear_frames(error.__traceback__)
            error.__traceback__ = None
        finally:
            await self.clean_up(writer)

    async def controller_com(self):
        while True:
            server_writer = None
            try:
                server_reader, server_writer = self.open_connection((self.config['localhost_ip'], self.config['localhost_port']['controller'][0]))
                server_writer.write(b"31a8e78e-af98-40ed-ba08-7471b444fe40")
                await server_writer.drain()
                while True:
                    server_writer.write(str(self.ID).encode('utf-8') + b"\n" + json.dumps(self.future_pool, default=self.replace_set).encode('utf-8'))
                    await server_writer.drain()
            except Exception as error:
                traceback.clear_frames(error.__traceback__)
                error.__traceback__ = None
                await self.clean_up(server_writer)

    def is_china_ip(self, ip):
        return self.ip_in_it(ip, self.geoip_list)

    @staticmethod
    def ip_in_it(ip: bytes, var):
        if isinstance(ip, str):
            ip = ip.encode('utf-8')
        ip = ip.replace(b'::ffff:', b'', 1)
        ip = int(ipaddress.ip_address(ip.decode('utf-8')))
        left = 0
        right = len(var) - 1
        while left <= right:
            mid = left + (right - left) // 2
            if var[mid][0] <= ip <= var[mid][1]:
                return True
            elif var[mid][1] < ip:
                left = mid + 1
            elif var[mid][0] > ip:
                right = mid - 1
        return False

    @staticmethod
    def replace_set(obj):
        if isinstance(obj, set):
            return list(obj)

    def exception_handler(self, loop, context):
        pass


class pangolin_balancer(pgl_base, pgl_connect):
    def __int__(self, config):
        super().__init__()
        self.init(config)

    def init(self, config):
        gc.set_threshold(100000, 50, 50)
        self.async_queue_s2p = asyncio.Queue()
        self.processor_future = self.loop.create_future()
        self.com_future = self.loop.create_future()
        self.config = config
        self.set_priority('above_normal')
        self.create_loop()

    def create_loop(self):
        self.loop = asyncio.new_event_loop()
        self.loop.set_exception_handler(self.exception_handler)
        for x in self.config['servers'].keys():
            self.loop.create_task(self.create_server_sock(self.config['servers'][x]['listen']))
        self.loop.create_task(self.sock_processor())
        self.loop.create_task(self.controller_com())
        self.loop.run_forever()

    async def create_server_sock(self, port: int):
        listener = self.get_listener(port, False)
        while True:
            sock = None
            try:
                sock, _ = await self.loop.sock_accept(listener)
                sock.setblocking(False)
                await self.async_queue_s2p.put(sock)
            except Exception as error:
                traceback.clear_frames(error.__traceback__)
                error.__traceback__ = None
                await self.clean_up(sock)

    async def sock_processor(self):
        while True:
            try:
                sock = await self.async_queue_s2p.get()
                self.com_future.set_result(sock.getpeername()[0].encode('utf-8') + b"\n" + str(sock.getsockname()[1]).encode('utf-8'))
                ID, IP = await self.processor_future
                await self.config['pipes_sock'][int(ID)][1].coro_send((sock, IP.decode('utf-8')))
            except Exception as error:
                traceback.clear_frames(error.__traceback__)
                error.__traceback__ = None

    async def controller_com(self):
        while True:
            server_writer = None
            try:
                server_reader, server_writer = self.open_connection((self.config['localhost_ip'], self.config['localhost_port']['controller'][0]))
                server_writer.write(b"82b28d69-e47f-4a25-a700-84eba7c2a80d")
                await server_writer.drain()
                while True:
                    data = await self.com_future
                    server_writer.write(data)
                    await server_writer.drain()
                    ID, IP = (await asyncio.wait_for(server_reader.read(4096), 10)).split(b"\n")
                    self.processor_future.set_result((ID, IP))
            except Exception as error:
                traceback.clear_frames(error.__traceback__)
                error.__traceback__ = None
                await self.clean_up(server_writer)

    def exception_handler(self, loop, context):
        pass


class pangolin_daemon(pgl_base):
    def __int__(self):
        super().__init__()
        self.init()

    def init(self):
        gc.set_threshold(100000, 50, 50)
        self.service = []
        self.load_config()
        self.load_exception_list()
        self.create_pipes()
        self.run_service()
        self.set_priority('above_normal')

    def run_service(self):
        self.service.append(aioprocessing.AioProcess(target=pangolin_controller, args=(self.config, )))
        self.service.append(aioprocessing.AioProcess(target=pangolin_balancer, args=(self.config, )))
        for x in range(os.cpu_count()):
            self.service.append(aioprocessing.AioProcess(target=pangolin_core, args=(self.config, x, )))
        for x in self.service:
            x.start()
        for x in self.service:
            x.join()

    def load_config(self):
        self.config_path = os.path.abspath(os.path.dirname(sys.argv[0])) + "/"
        if os.path.exists(self.config_path + 'config.json'):
            with open(self.config_path + 'config.json', 'r') as file:
                content = file.read()
            content = self.translate(content)
            self.config = json.loads(content)
            if socket.has_dualstack_ipv6():
                self.config['localhost_ip'] = '::1'
                self.config['remote_ip'] = '::'
                self.config['has_ipv6'] = True
            else:
                self.config['localhost_ip'] = '127.0.0.1'
                self.config['remote_ip'] = '0.0.0.0'
                self.config['has_ipv6'] = False
            self.config['localhost_port'] = dict()
            self.config['remote_port'] = dict()
            self.config['remote_port']['core'] = self.find_available_port(self.calculate_ports(self.config['uuid'] + 'core'), num=2)
            self.config['remote_port']['controller'] = self.find_available_port(self.calculate_ports(self.config['uuid'] + 'controller'), self.config['remote_port']['core'])
            self.config['localhost_port']['controller'] = self.find_available_port(exception=self.config['remote_port']['core'] + self.config['remote_port']['controller'])
            keys = list()
            for x in self.config['keys']:
                keys.append(x.encode('utf-8'))
            self.config['keys'] = keys
            self.config['port2service'] = dict()
            self.config['port2port'] = dict()
            for x in self.config['services'].keys():
                self.config['port2service'][int(self.config['services'][x]['listen'])] = x.lower()
            for x in self.config['services'].keys():
                self.config['port2port'][int(self.config['services'][x]['listen'])] = int(self.config['services'][x]['sendto'])
            print(self.config)
        else:
            example = {"uuid": "", "geoip": "", "TCP_pool_size": "", "services": {"example": {"listen": "", "sendto": ""}},
                       "keys": [""], "ssl": {"cert": "", "key": ""}}
            with open(self.config_path + 'config.json', 'w') as file:
                json.dump(example, file, indent=4)

    def load_exception_list(self):
        def load_list(location, var, funcs, replace):
            if location and not os.path.exists(location):
                with open(location, 'w') as file:
                    json.dump([], file)
                    file.flush()
            if location:
                with open(location, 'r') as file:
                    data = json.load(file)
                for func in funcs:
                    data = list(map(func, data))
                for x in data:
                    for y in replace:
                        x = x.replace(y[0], y[1], y[2])
                    var.add(x)
        self.geoip_list = []
        with open(self.config['geoip'], 'r') as file:
            data = json.load(file)
        for x in data:
            network = ipaddress.ip_network(x)
            self.geoip_list.append([int(network[0]), int(network[-1])])
        self.config['geoip_list'] = self.geoip_list

    def create_pipes(self):
        self.config['pipes_sock'] = dict()
        for x in range(os.cpu_count()):
            self.config['pipes_sock'][x] = (aioprocessing.AioPipe(False))


if __name__ == '__main__':
    pangolin_daemon().init()
