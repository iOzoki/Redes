#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <thread>
#include <vector>
#include <mutex>
#include <string>
#include <algorithm>
#include <memory>

#pragma comment(lib, "Ws2_32.lib")

#define PORTA_SERVIDOR 12345
#define TAMANHO_BUFFER 1024

namespace Servidor {

    namespace Model {
        std::atomic<long> proximoIdMensagem(1);

        long gerarIdUnicoParaMensagem() {
            return proximoIdMensagem.fetch_add(1);
        }

        class Usuario {
        private:
            uint32_t id;
            std::string username;
            std::string passwordHash;
            std::string salt;
            bool online;
            time_t ultimoLoginTimestamp;

        public:
            Usuario(uint32_t id,const std::string& uname, const std::string& pHash, const std::string& s)
                : id(id), username(uname), passwordHash(pHash), salt(s), online(false), ultimoLoginTimestamp(0) {
            }

            uint32_t getId() const {
                return id;
            }

            void setId(uint32_t novoId) {
                id = novoId;
            }


            std::string getUsername() const {
                return username;
            }

            std::string getSalt() const {
                return salt;
            }

            bool isOnline() const {
                return online;
            }

            time_t getUltimoLoginTimestamp() const {
                return ultimoLoginTimestamp;
            }

            void setOnline(bool status) {
                this->online = status;
            }

            void setUltimoLoginTimestamp(time_t timestamp) {
                this->ultimoLoginTimestamp = timestamp;
            }

            bool verificarHashSenha(const std::string& hashSenhaFornecida) const {
                return this->passwordHash == hashSenhaFornecida;
            }

        };

        class Mensagem {
        private:
            long idMensagem;
            std::string remetente;
            std::string destinatario;
            std::string conteudo;
            long long timestamp;
            bool entregue;

        public:
            Mensagem(const std::string& rem, const std::string& dest, const std::string& cont)
                : idMensagem(gerarIdUnicoParaMensagem()),
                  remetente(rem),
                  destinatario(dest),
                  conteudo(cont),
                  entregue(false) {
                timestamp = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
            }

            long getIdMensagem() const {
                return idMensagem;
            }

            std::string getRemetente() const {
                return remetente;
            }

            std::string getDestinatario() const {
                return destinatario;
            }

            std::string getConteudo() const {
                return conteudo;
            }

            long long getTimestamp() const {
                return timestamp;
            }

            bool isEntregue() const {
                return entregue;
            }

            void marcarComoEntregue(bool status) {
                this->entregue = status;
            }
        };


    }

    namespace Controller {

        // Forward declaration da classe ChatServidor para que TratadorCliente possa referenciá-la
        class ChatServidor;

        class TratadorCliente {
        private:
            SOCKET socketCliente;
            ChatServidor* instanciaServidor; // Ponteiro para a instância do servidor principal

        public:
            TratadorCliente(SOCKET socket, ChatServidor* servidor)
                : socketCliente(socket), instanciaServidor(servidor) {
                // Construtor inicializa o socket do cliente e a referência ao servidor
            }

            ~TratadorCliente() {
                // O socket do cliente é fechado pelo ChatServidor ao remover o cliente.
                // Se houvesse outros recursos alocados especificamente pelo TratadorCliente,
                // seriam liberados aqui.
            }

            // Método que contém a lógica que estava na função global handle_client()
            void processarComunicacaoCliente();
        };

        class ChatServidor {
        private:
            SOCKET socketServidorOuvinte; // Socket que escuta por novas conexões
            sockaddr_in enderecoServidor;
            std::vector<std::unique_ptr<std::thread>> threadsClientes; // Armazena as threads dos clientes
            std::vector<SOCKET> socketsClientesAtivos; // Lista de sockets dos clientes ativos
            std::mutex mutexSocketsClientes;       // Mutex para proteger o acesso a socketsClientesAtivos

            // Métodos privados para organização interna da inicialização e limpeza
            bool inicializarWinsock() {
                WSADATA wsaData;
                int resultado = WSAStartup(MAKEWORD(2, 2), &wsaData);
                if (resultado != 0) {
                    std::cerr << "WSAStartup falhou com erro: " << resultado << std::endl;
                    return false;
                }
                std::cout << "Winsock inicializado." << std::endl;
                return true;
            }

            bool criarSocketOuvinte() {
                socketServidorOuvinte = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
                if (socketServidorOuvinte == INVALID_SOCKET) {
                    std::cerr << "Erro ao criar socket ouvinte: " << WSAGetLastError() << std::endl;
                    return false;
                }
                std::cout << "Socket ouvinte criado." << std::endl;
                return true;
            }

            void configurarEnderecoServidor(int porta) {
                enderecoServidor.sin_family = AF_INET;
                enderecoServidor.sin_addr.s_addr = INADDR_ANY; // Escuta em todas as interfaces de rede
                enderecoServidor.sin_port = htons(porta);
                std::cout << "Endereco do servidor configurado para a porta " << porta << "." << std::endl;
            }

            bool vincularSocketOuvinte() {
                if (bind(socketServidorOuvinte, (sockaddr*)&enderecoServidor, sizeof(enderecoServidor)) == SOCKET_ERROR) {
                    std::cerr << "Erro no bind do socket ouvinte: " << WSAGetLastError() << std::endl;
                    return false;
                }
                std::cout << "Socket ouvinte vinculado ao endereco." << std::endl;
                return true;
            }

            bool iniciarEscuta() {
                if (listen(socketServidorOuvinte, SOMAXCONN) == SOCKET_ERROR) {
                    std::cerr << "Erro no listen do socket ouvinte: " << WSAGetLastError() << std::endl;
                    return false;
                }
                std::cout << "Servidor escutando por conexoes..." << std::endl;
                return true;
            }

            void limparRecursosWinsock() {
                WSACleanup();
                std::cout << "Recursos Winsock liberados." << std::endl;
            }

            void fecharSocketOuvinte() {
                if (socketServidorOuvinte != INVALID_SOCKET) {
                    closesocket(socketServidorOuvinte);
                    socketServidorOuvinte = INVALID_SOCKET;
                    std::cout << "Socket ouvinte fechado." << std::endl;
                }
            }

        public:
            ChatServidor() : socketServidorOuvinte(INVALID_SOCKET) {
                // Construtor padrão
            }

            ~ChatServidor() {
                // Garante que os sockets e o Winsock sejam limpos ao destruir o objeto
                std::cout << "Destruindo ChatServidor..." << std::endl;
                for (const auto& s : socketsClientesAtivos) {
                     closesocket(s); // Fecha todos os sockets de cliente restantes
                }
                fecharSocketOuvinte();
                limparRecursosWinsock();

                // Espera que todas as threads de cliente terminem (join)
                // Em um servidor real, seria importante sinalizar para as threads terminarem
                // antes de fazer o join, para evitar bloqueios indefinidos.
                // Por simplicidade e para manter o comportamento de detach do código original,
                // a gestão explícita de join não foi adicionada aqui, mas é uma consideração importante.
            }

            // Método principal para iniciar e rodar o servidor
            void iniciar(int porta) {
                if (!inicializarWinsock()) {
                    return;
                }
                if (!criarSocketOuvinte()) {
                    limparRecursosWinsock();
                    return;
                }
                configurarEnderecoServidor(porta);
                if (!vincularSocketOuvinte()) {
                    fecharSocketOuvinte();
                    limparRecursosWinsock();
                    return;
                }
                if (!iniciarEscuta()) {
                    fecharSocketOuvinte();
                    limparRecursosWinsock();
                    return;
                }

                // Loop principal para aceitar novas conexões de clientes
                while (true) {
                    SOCKET socketNovoCliente = accept(socketServidorOuvinte, nullptr, nullptr);
                    if (socketNovoCliente == INVALID_SOCKET) {
                        std::cerr << "Erro no accept: " << WSAGetLastError() << std::endl;
                        // Considerar se o erro é fatal para o socket ouvinte.
                        // Se for, pode ser necessário sair do loop ou recriar o socket ouvinte.
                        // Por ora, continua tentando aceitar novas conexões.
                        continue;
                    }

                    std::cout << "Novo cliente conectado. Socket: " << socketNovoCliente << std::endl;
                    adicionarClienteSocket(socketNovoCliente);

                    // Cria e inicia uma nova thread para lidar com este cliente.
                    // O objeto TratadorCliente é criado dinamicamente e a thread assume sua posse.
                    // Usamos uma lambda para capturar as variáveis necessárias e chamar o método.
                    // A thread será detached, como no código original.
                    std::thread threadDoCliente([socketNovoCliente, this]() {
                        // Cria o objeto TratadorCliente na stack da thread ou dinamicamente
                        TratadorCliente tratador(socketNovoCliente, this);
                        tratador.processarComunicacaoCliente();
                    });
                    threadDoCliente.detach(); // Libera a thread para rodar independentemente.
                                            // threadsClientes.push_back(std::make_unique<std::thread>(std::move(threadDoCliente))); // Se fosse gerenciar com join
                }
            }

            // Adiciona um socket de cliente à lista de sockets ativos
            void adicionarClienteSocket(SOCKET socketCliente) {
                std::lock_guard<std::mutex> lock(mutexSocketsClientes);
                socketsClientesAtivos.push_back(socketCliente);
            }

            // Remove um socket de cliente da lista e fecha o socket
            void removerClienteSocket(SOCKET socketCliente) {
                std::lock_guard<std::mutex> lock(mutexSocketsClientes);
                // Encontra e remove o socket da lista de ativos
                socketsClientesAtivos.erase(
                    std::remove(socketsClientesAtivos.begin(), socketsClientesAtivos.end(), socketCliente),
                    socketsClientesAtivos.end()
                );
                closesocket(socketCliente); // Fecha o socket do cliente
                std::cout << "Cliente desconectado. Socket: " << socketCliente << " removido e fechado." << std::endl;
            }
        }; // Fim da classe ChatServidor

        // Implementação do método processarComunicacaoCliente da classe TratadorCliente
        // (Definida aqui após a definição completa de ChatServidor, pois TratadorCliente o utiliza)
        void TratadorCliente::processarComunicacaoCliente() {
            char buffer[TAMANHO_BUFFER];
            std::string mensagemBoasVindas = "Bem-vindo ao servidor de eco!\n";

            // Envia mensagem de boas-vindas ao cliente
            send(socketCliente, mensagemBoasVindas.c_str(), (int)mensagemBoasVindas.length(), 0);

            int bytesRecebidos;
            // Loop para receber e ecoar mensagens
            while ((bytesRecebidos = recv(socketCliente, buffer, TAMANHO_BUFFER - 1, 0)) > 0) {
                buffer[bytesRecebidos] = '\0'; // Garante terminação nula da string
                std::cout << "Socket " << socketCliente << " recebeu: " << buffer; // O buffer já pode conter \n

                // Ecoa a mensagem de volta para o cliente
                if (send(socketCliente, buffer, bytesRecebidos, 0) == SOCKET_ERROR) {
                    std::cerr << "Erro ao enviar dados para o socket " << socketCliente << ": " << WSAGetLastError() << std::endl;
                    break; // Sai do loop se houver erro no send
                }
            }

            if (bytesRecebidos == 0) {
                std::cout << "Socket " << socketCliente << " desconectou graciosamente." << std::endl;
            } else if (bytesRecebidos == SOCKET_ERROR) {
                std::cerr << "Erro no recv para o socket " << socketCliente << ": " << WSAGetLastError() << std::endl;
            }

            // Quando o loop termina (cliente desconectou ou erro), notifica o servidor para remover o cliente.
            // O instanciaServidor é um ponteiro para o ChatServidor.
            if (instanciaServidor != nullptr) {
                instanciaServidor->removerClienteSocket(socketCliente);
            } else {
                // Fallback: se por algum motivo instanciaServidor for nulo (não deveria acontecer)
                std::cerr << "Erro: instanciaServidor eh nulo em TratadorCliente. Fechando socket diretamente." << std::endl;
                closesocket(socketCliente);
            }
        }

    } // fim do namespace Controller

} // fim do namespace Servidor


int main() {
    // Cria uma instância do servidor
    Servidor::Controller::ChatServidor meuServidor;

    // Inicia o servidor na porta definida
    meuServidor.iniciar(PORTA_SERVIDOR);

    // A execução do servidor ocorre dentro do método iniciar() e seu loop de accept.
    // O programa normalmente não chegaria aqui a menos que o loop de accept fosse interrompido
    // de forma controlada (o que não está implementado neste exemplo simples).
    std::cout << "Servidor principal encerrando (isso nao deveria acontecer em operacao normal)." << std::endl;
    return 0;
}
