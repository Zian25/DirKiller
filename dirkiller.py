# -*- coding:utf-8 -*-
import sys
import requests
import argparse
import os as terminal
import re
sys.path.append("modulos")

parser = argparse.ArgumentParser(description='dirkiller.py -h para ver a tela de ajuda')
parser.add_argument("-u", help="Insira o dominio aqui", required=True, dest="host", action="store")
parser.add_argument("-p", help="Porta do host", required=False, dest="porta", action="store")
parser.add_argument("-w", help="wordlist", required=False, dest="word", action="store")
parser.add_argument("--ssl", help="Em casos de uso de HTTPS não identificado", required=False, dest="ssl_inp", action="store_true")
parser.add_argument("-o", help="Insira o Sistema Operacional do host (Unix/Linux/Windows)", required=False, dest="os", action="store")
parser.add_argument("-v", help="Modo Verbose", required=False, dest="verbose", action="store_true")
parser.add_argument("-v2", help="Modo Verbose ++", required=False, dest="verbose2", action="store_true")
# parser.add_argument("-sp", help="Busca diretorios sensiveis", required=False, dest="sensiveis", action="store_true")


args = parser.parse_args()
vuln = 0
vuln_link = []
ssl = False
wordl = False
tentativa = 0
os = "undef"
checker = terminal.popen("git pull").read()
if re.search("Already up to date.", checker):
	print ("[+] Não há atualizações, o sistema pode prosseguir.")
else:
	print ("[!] DirKiller foi atualizado, inicie novamente para aplicar a atualização")
			
if args.host:
	# Aqui inicia os checks	
	if args.host.startswith("http://"):
		host = args.host.replace("http://", "")
		ssl = False
		init = "http://"

	elif args.host.startswith("https://"):
		host = args.host.replace("https://", "")
		ssl = True
		init = "https://"	

	elif args.host.startswith("www."):
		host = args.host.replace("www.", "")
		init = "www."


	elif args.host.isdigit():
		host = args.host
		init = "http://"


	else:
		host = args.host
		init = input("Digite o protocolo (Ex: http://, https://): ")

	if host.endswith("/"):
		host = host.replace("/", "")

	#---------------------------------
	if args.porta:
		print (f"[+] Iniciando varredura em {host} na porta {args.porta}")
	else:
		print (f"[+] Iniciando varredura em {host}")
	#----------------------------------

	if args.verbose:
		print ("[+] Modo Verbose ativado") 

	elif args.verbose2:
		print ("[+] Modo Verbose++ ativado")

	else:
		print("[i] Modo Verbose não está habilitado, quando houver vulneraveis, aparecerá")
		print ("[i] Aguarde até aparecer")


	if ssl == True or args.ssl_inp:
		porta = 443

	elif args.porta:
		porta = int(args.porta)

	else:
		porta = 80

	if args.os:
		if args.os.lower() == "windows":
			os = "Windows"
			print ("[i] Usando Path's para Windows\n")
		elif args.os.lower() == "unix" or args.os.lower() == "linux":
			os = "Unix/Linux"
			print ("[i] Usando Path's para Unix/Linux\n")

		else:
			os = "undef"
			print ("[i] Usando Path's de todos os sistemas\n")

	print ("[i] Pressione CTRL+C para encerrar\n")
	
	if args.word:
		wordl = True
		wordlist = open(args.word, "r", encoding="utf8")

	if os == "Windows" and wordl == False:
		wordlist = open("modulos/winkiller.txt", "r", encoding="utf8")

	elif os == "Unix/Linux" and wordl == False:
		wordlist = open("modulos/unixkiller.txt", "r", encoding="utf8")

	elif os == "undef" and wordl == False:
		wordlist = open("modulos/killer.txt", "r", encoding="utf8")

	for linha in wordlist:
		try:
			r = requests.head(f"{init}{host}:{porta}/{linha}")
			tentativa = tentativa + 1
				
			if int(r.status_code) >= 400:
				if args.verbose:
					print(f"[-] {r.url}")

				elif args.verbose2:
					print (f"[-]  Status:{r.status_code} URL: {r.url}")

			elif int(r.status_code) == 403:
				print (f"[-] WAF: {r.url} ")

			elif int(r.status_code) >= 200 and int(r.status_code) <300:
				vuln_link.append(r.url)
				if args.verbose2:
					print (f"[+] Status:{r.status_code}: {r.url} <-- Vulnerável")

				else:
					print (f"[+] {r.url} <-- Vulnerável")

				vuln = vuln + 1


		except KeyboardInterrupt:
			print (f"\nVulneráveis: {vuln}")
			print(f"Tentativas:{tentativa}\n")
			if vuln >0:
				for item in vuln_link:
					print (item+" <-- Vulnerável")

			else:
				pass
			exit(0)

		except requests.exceptions.InvalidSchema:
			print("Não foi possivel conectar! Verifique a porta e parametros")
			break

		except requests.exceptions.ConnectionError:
			print(f"Não foi possivel conectar com {host} na porta {porta}\n")
			if porta == 443:
				print ("Verifique se o host tem SSL/TLS, use http:// ou -p 80 ou apenas o host se não tiver SSL/TLS")
			print (f"Verifique todos os parametros\n")
			break
			pass


	print("Fim da varredura.\n")
	print (f"\nVulneráveis: {vuln}")
	print(f"Tentativas:{tentativa}\n")
	if vuln >0:
		for item in vuln_link:
			print (item+" <-- Vulnerável")
