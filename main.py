from traceroute import Traceroute
from arguments import create_parser

if __name__ == '__main__':
    input_data = create_parser()
    tracerouter = Traceroute(input_data)
    tracerouter.find_route()
