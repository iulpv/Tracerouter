import argparse


def create_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument('IP_ADDRESS', help='ip', type=str, action='store')
    parser.add_argument('-t', default=2, type=float, help='timeout (по умолчанию 2с)')
    parser.add_argument('-p', type=int, action='store', help='port (для tcp или udp)', required=False)
    parser.add_argument('-ttl', type=int, action='store', default=30, help='максимальное количество запросов')
    parser.add_argument('protocol', type=str, action='store', help='протокол {tcp|udp|icmp}',
                        choices=['tcp', 'udp', 'icmp'])
    parser.add_argument('-i', default=0, type=float, help='интервал между запросами')
    parser.add_argument('-s', default=40, type=int, help='размер пакета (по умолчанию 40)')
    parser.add_argument('-r', default=3, type=int, help='запросы (по умолчанию 3)')
    return parser.parse_args()
