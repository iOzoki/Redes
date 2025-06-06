#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <thread>
#include <vector>
#include <mutex>
#include <string>
#include <algorithm>
#include <memory>
#include <atomic>
#include <sstream>
#include <map>
#include <fstream>
#include <stdexcept>
#include <chrono>

#pragma comment(lib, "Ws2_32.lib")

#define PORTA_SERVIDOR 12345
#define TAMANHO_BUFFER 1024

namespace CryptoUtils {

    class SHA256 {
    protected:
        typedef unsigned char uint8;
        typedef unsigned int uint32;
        typedef unsigned long long uint64;

        const static uint32 sha256_k[];
        static const unsigned int SHA224_256_BLOCK_SIZE = (512 / 8);
    public:
        void init();
        void update(const unsigned char* message, unsigned int len);
        void final(unsigned char* digest);
        static const unsigned int DIGEST_SIZE = (256 / 8);

    protected:
        void transform(const unsigned char* message, unsigned int block_nb);
        unsigned int m_tot_len;
        unsigned int m_len;
        unsigned char m_block[2 * SHA224_256_BLOCK_SIZE];
        uint32 m_h[8];
    };

    std::string sha256(const std::string& input);

    // Definição das constantes e métodos da classe SHA256
#define SHA2_SHFR(x, n)    (x >> n)
#define SHA2_ROTR(x, n)   ((x >> n) | (x << ((sizeof(x) << 3) - n)))
#define SHA2_ROTL(x, n)   ((x << n) | (x >> ((sizeof(x) << 3) - n)))
#define SHA2_CH(x, y, z)  ((x & y) ^ (~x & z))
#define SHA2_MAJ(x, y, z) ((x & y) ^ (x & z) ^ (y & z))
#define SHA256_F1(x) (SHA2_ROTR(x,  2) ^ SHA2_ROTR(x, 13) ^ SHA2_ROTR(x, 22))
#define SHA256_F2(x) (SHA2_ROTR(x,  6) ^ SHA2_ROTR(x, 11) ^ SHA2_ROTR(x, 25))
#define SHA256_F3(x) (SHA2_ROTR(x,  7) ^ SHA2_ROTR(x, 18) ^ SHA2_SHFR(x,  3))
#define SHA256_F4(x) (SHA2_ROTR(x, 17) ^ SHA2_ROTR(x, 19) ^ SHA2_SHFR(x, 10))
#define SHA2_UNPACK32(x, str)                 \
    {                                         \
        *((str) + 3) = (uint8) ((x)      );   \
        *((str) + 2) = (uint8) ((x) >>  8);   \
        *((str) + 1) = (uint8) ((x) >> 16);   \
        *((str) + 0) = (uint8) ((x) >> 24);   \
    }
#define SHA2_PACK32(str, x)                   \
    {                                         \
        *(x) =   ((uint32) *((str) + 3)      ) \
               | ((uint32) *((str) + 2) <<  8) \
               | ((uint32) *((str) + 1) << 16) \
               | ((uint32) *((str) + 0) << 24);   \
    }
    const unsigned int SHA256::sha256_k[64] = // K_shafour
    { 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
      0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
      0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
      0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
      0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
      0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
      0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
      0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
      0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
      0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
      0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
      0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
      0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
      0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 };

    void SHA256::transform(const unsigned char* message, unsigned int block_nb) {
        uint32 w[64];
        uint32 wv[8];
        uint32 t1, t2;
        const unsigned char* sub_block;
        int i;
        int j;
        for (i = 0; i < (int)block_nb; i++) {
            sub_block = message + (i << 6);
            for (j = 0; j < 16; j++) {
                SHA2_PACK32(&sub_block[j << 2], &w[j]);
            }
            for (j = 16; j < 64; j++) {
                w[j] = SHA256_F4(w[j - 2]) + w[j - 7] + SHA256_F3(w[j - 15]) + w[j - 16];
            }
            for (j = 0; j < 8; j++) {
                wv[j] = m_h[j];
            }
            for (j = 0; j < 64; j++) {
                t1 = wv[7] + SHA256_F2(wv[4]) + SHA2_CH(wv[4], wv[5], wv[6]) + sha256_k[j] + w[j];
                t2 = SHA256_F1(wv[0]) + SHA2_MAJ(wv[0], wv[1], wv[2]);
                wv[7] = wv[6];
                wv[6] = wv[5];
                wv[5] = wv[4];
                wv[4] = wv[3] + t1;
                wv[3] = wv[2];
                wv[2] = wv[1];
                wv[1] = wv[0];
                wv[0] = t1 + t2;
            }
            for (j = 0; j < 8; j++) {
                m_h[j] += wv[j];
            }
        }
    }

    void SHA256::init() {
        m_h[0] = 0x6a09e667;
        m_h[1] = 0xbb67ae85;
        m_h[2] = 0x3c6ef372;
        m_h[3] = 0xa54ff53a;
        m_h[4] = 0x510e527f;
        m_h[5] = 0x9b05688c;
        m_h[6] = 0x1f83d9ab;
        m_h[7] = 0x5be0cd19;
        m_len = 0;
        m_tot_len = 0;
    }

    void SHA256::update(const unsigned char* message, unsigned int len) {
        unsigned int block_nb;
        unsigned int new_len, rem_len, tmp_len;
        const unsigned char* shifted_message;
        tmp_len = SHA224_256_BLOCK_SIZE - m_len;
        rem_len = len < tmp_len ? len : tmp_len;
        memcpy(&m_block[m_len], message, rem_len);
        if (m_len + len < SHA224_256_BLOCK_SIZE) {
            m_len += len;
            return;
        }
        new_len = len - rem_len;
        block_nb = new_len / SHA224_256_BLOCK_SIZE;
        shifted_message = message + rem_len;
        transform(m_block, 1);
        transform(shifted_message, block_nb);
        rem_len = new_len % SHA224_256_BLOCK_SIZE;
        memcpy(m_block, &shifted_message[block_nb << 6], rem_len);
        m_len = rem_len;
        m_tot_len += (block_nb + 1) << 6;
    }

    void SHA256::final(unsigned char* digest) {
        unsigned int block_nb;
        unsigned int pm_len;
        unsigned int len_b;
        int i;
        block_nb = (1 + ((SHA224_256_BLOCK_SIZE - 9)
            < (m_len % SHA224_256_BLOCK_SIZE)));
        len_b = (m_tot_len + m_len) << 3;
        pm_len = block_nb << 6;
        memset(m_block + m_len, 0, pm_len - m_len);
        m_block[m_len] = 0x80;
        SHA2_UNPACK32(len_b, m_block + pm_len - 4);
        transform(m_block, block_nb);
        for (i = 0; i < 8; i++) {
            SHA2_UNPACK32(m_h[i], &digest[i << 2]);
        }
    }

    std::string sha256(const std::string& input) {
        unsigned char digest[SHA256::DIGEST_SIZE];
        memset(digest, 0, SHA256::DIGEST_SIZE);

        SHA256 ctx = SHA256();
        ctx.init();
        ctx.update((unsigned char*)input.c_str(), input.length());
        ctx.final(digest);

        char buf[2 * SHA256::DIGEST_SIZE + 1];
        buf[2 * SHA256::DIGEST_SIZE] = 0;
        for (int i = 0; i < SHA256::DIGEST_SIZE; i++) {
            sprintf_s(buf + i * 2, 3, "%02x", digest[i]);
        }
        return std::string(buf);
    }

    // Função para gerar um salt aleatório
    std::string gerarSalt(size_t tamanho = 16) {
        const std::string CARACTERES = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        std::random_device random_device;
        std::mt19937 generator(random_device());
        std::uniform_int_distribution<> distribution(0, CARACTERES.size() - 1);
        std::string random_string;
        for (std::size_t i = 0; i < tamanho; ++i) {
            random_string += CARACTERES[distribution(generator)];
        }
        return random_string;
    }

    // Função para calcular o hash de uma senha com um salt
    std::string calcularHash(const std::string& senha, const std::string& salt) {
        return sha256(senha + salt);
    }
}

namespace Servidor {

    namespace Model {
        std::atomic<uint64_t> proximoIdMensagem(1);

        uint64_t gerarIdUnicoParaMensagem() {
            return proximoIdMensagem.fetch_add(1);
        }

        class Usuario {
        private:
            const uint32_t id;
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

            std::string getPasswordHashParaSalvar() const { return passwordHash; }

        };

        class Mensagem {
        private:
            uint64_t idMensagem;
            uint32_t idRemetente;
            uint32_t idDestinatario;
            std::string conteudo;
            uint64_t timestamp;
            bool entregue;

        public:
            Mensagem(uint32_t remetenteId, uint32_t destinatarioId, const std::string& textoConteudo)
            : idMensagem(gerarIdUnicoParaMensagem()),
            idRemetente(remetenteId),
            idDestinatario(destinatarioId),
            conteudo(textoConteudo),
            entregue(false) {
                timestamp = static_cast<uint64_t>(std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()));
            }

            uint64_t getIdMensagem() const { return idMensagem; }

            uint32_t getIdRemetente() const { return idRemetente; }

            uint32_t getIdDestinatario() const { return idDestinatario; }

            const std::string& getConteudo() const { return conteudo; }

            uint64_t getTimestamp() const { return timestamp; }

            bool foiEntregue() const { return entregue; }

            void marcarComoEntregue() { entregue = true; }

        };

    } //fim do namespace Model

    namespace Controller {

        class ChatServidor;

        class TratadorCliente {
        private:
            SOCKET socketCliente;
            ChatServidor* instanciaServidor;
            Persistencia::GerenciadorUsuarios* gerenciadorUsuarios; // *** NOVO: Ponteiro para o gerenciador ***
            std::unique_ptr<Model::Usuario> usuarioLogado;
            std::string bufferRecepcao;

            std::vector<std::string> parseMensagem(const std::string& msg) {
                std::vector<std::string> partes;
                std::stringstream ss(msg);
                std::string parte;
                while (std::getline(ss, parte, '|')) {
                    partes.push_back(parte);
                }
                return partes;
            }

            void handleLogin(const std::vector<std::string>& params) {
                if (params.size() < 3) {
                    std::cerr << "Comando LOGIN mal formado." << std::endl;
                    return;
                }
                const std::string& username = params[1];
                const std::string& password = params[2];

                std::cout << "Tentativa de login para o usuario: " << username << std::endl;

                std::string resposta = "LOGIN_OK|ana,1;beto,0;carlos,1\n";
                send(socketCliente, resposta.c_str(), resposta.length(), 0);
            }

            void handleEnvioMensagem(const std::vector<std::string>& params) {
                if (params.size() < 3) return;
                std::cout << "Usuario " << (usuarioLogado ? usuarioLogado->getUsername() : "N/A")
                          << " enviou mensagem para " << params[1] << ": " << params[2] << std::endl;
            }

            void handleRegistro(const std::vector<std::string>& params){
                std::cout << "Tentativa de registro..." << std::endl;
            }


        public:
            TratadorCliente(SOCKET socket, ChatServidor* servidor, Persistencia::GerenciadorUsuarios* gerenciador)
                : socketCliente(socket), instanciaServidor(servidor), gerenciadorUsuarios(gerenciador), usuarioLogado(nullptr) {
            }

            ~TratadorCliente() {
                if (usuarioLogado) {
                    std::cout << "Limpando tratador para o usuario: " << usuarioLogado->getUsername() << std::endl;
                }
                closesocket(socketCliente);
            }

            // Método que contém a lógica que estava na função global handle_client()
            void processarComunicacaoCliente() {
                char buffer[TAMANHO_BUFFER];
                int bytesRecebidos;
                while ((bytesRecebidos = recv(socketCliente, buffer, TAMANHO_BUFFER, 0)) > 0) {
                    bufferRecepcao.append(buffer, bytesRecebidos);
                    size_t pos;

                    while ((pos = bufferRecepcao.find('\n')) != std::string::npos) {
                        std::string mensagemCompleta = bufferRecepcao.substr(0, pos);
                        bufferRecepcao.erase(0, pos + 1);
                        if (!mensagemCompleta.empty()) {
                            std::cout << "Recebido comando completo: " << mensagemCompleta << std::endl;
                            std::vector<std::string> partes = parseMensagem(mensagemCompleta);

                            if (partes.empty()) continue;
                            const std::string& comando = partes[0];

                            if (comando == "LOGIN") {
                                handleLogin(partes);
                            }
                            else if (comando == "REGISTRO") {
                                handleRegistro(partes);
                            }
                            else if (comando == "MSG") {
                                handleEnvioMensagem(partes);
                            }
                            else {
                                std::cerr << "Comando desconhecido recebido: " << comando << std::endl;
                            }
                        }
                    }
                }

                std::cout << "Cliente desconectou. Socket: " << socketCliente << std::endl;
            }
        };

        class ChatServidor {
        private:
            SOCKET socketServidorOuvinte;
            Persistencia::GerenciadorUsuarios gerenciadorUsuarios;
            std::map<uint32_t, TratadorCliente*> sessoesAtivas;
            std::mutex mutexSessoes;

            std::vector<std::string> parseMensagem(const std::string& msg) { /* ... */ return {}; }

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
                enderecoServidor.sin_addr.s_addr = INADDR_ANY;
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
            }

            ~ChatServidor() {
                std::cout << "Destruindo ChatServidor..." << std::endl;
                for (const auto& s : socketsClientesAtivos) {
                     closesocket(s); // Fecha todos os sockets de cliente restantes
                }
                fecharSocketOuvinte();
                limparRecursosWinsock();

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

                std::cout << "Servidor de Chat iniciado na porta " << porta << std::endl;

                while (true) {
                    SOCKET socketNovoCliente = accept(socketServidorOuvinte, nullptr, nullptr);
                    if (socketNovoCliente == INVALID_SOCKET) {
                        continue;
                    }

                    std::cout << "Novo cliente conectado. Socket: " << socketNovoCliente << std::endl;
                    adicionarClienteSocket(socketNovoCliente);

                    std::thread threadDoCliente([socketNovoCliente, this]() {
                        TratadorCliente tratador(socketNovoCliente, this);
                        tratador.processarComunicacaoCliente();
                        if (tratador->isLogado()) {
                             this->removerSessao(tratador->getUsuarioId());
                        }
                        delete tratador;
                    });
                    threadDoCliente.detach();
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
    namespace Persistencia {
        class GerenciadorUsuarios {
        private:
            const std::string nomeArquivo = "usuarios.dat";
            std::vector<std::shared_ptr<Model::Usuario>> usuariosEmMemoria;
            std::atomic<uint32_t> proximoIdDisponivel;
            std::mutex mutexUsuarios;

            void inicializarContadorDeId() {
                uint32_t maxId = 0;
                for (const auto& usuario : usuariosEmMemoria) {
                    if (usuario->getId() > maxId) {
                        maxId = usuario->getId();
                    }
                }
                proximoIdDisponivel = maxId + 1;
            }

            void escreverString(std::ofstream& arquivo, const std::string& str) {
                size_t tamanho = str.size();
                arquivo.write(reinterpret_cast<const char*>(&tamanho), sizeof(tamanho));
                arquivo.write(str.c_str(), tamanho);
            }

            std::string lerString(std::ifstream& arquivo) {
                size_t tamanho;
                arquivo.read(reinterpret_cast<char*>(&tamanho), sizeof(tamanho));

                if (arquivo.eof()) return "";

                std::string str(tamanho, '\0');
                arquivo.read(&str[0], tamanho);

                return str;
            }

        public:

            void salvarUsuario(const Model::Usuario& usuario) {
                std::lock_guard<std::mutex> lock(mutexUsuarios);

                if (!arquivo.is_open()) {
                    throw std::runtime_error("Nao foi possivel abrir o arquivo para escrita: " + nomeArquivo);
                }

                uint32_t id = usuario.getId();
                arquivo.write(reinterpret_cast<const char*>(&id), sizeof(id));

                escreverString(arquivo, usuario.getUsername());

                escreverString(arquivo, usuario.getSalt());

                time_t ultimoLogin = usuario.getUltimoLoginTimestamp();
                arquivo.write(reinterpret_cast<const char*>(&ultimoLogin), sizeof(ultimoLogin));

                arquivo.close();
            }

            void carregarUsuarios() {
                std::vector<Model::Usuario> usuarios;
                std::ifstream arquivo(nomeArquivo, std::ios::binary);

                if (!arquivo.is_open()) {
                    std::cout << "Arquivo de usuarios nao encontrado. Iniciando com base de dados vazia." << std::endl;
                    return usuarios; // Retorna um vetor vazio, o que é normal na primeira execução
                }

                while (arquivo.peek() != EOF) {
                    uint32_t id;
                    arquivo.read(reinterpret_cast<char*>(&id), sizeof(id));

                    if (arquivo.eof()) break;

                    std::string username = lerString(arquivo);
                    std::string salt = lerString(arquivo);
                    time_t ultimoLogin;
                    arquivo.read(reinterpret_cast<char*>(&ultimoLogin), sizeof(ultimoLogin));


                    // Recria o objeto Usuario com os dados lidos
                    // ATENÇÃO: para este exemplo funcionar, adicione um novo construtor à sua classe Usuario
                    // ou modifique o existente para lidar com o hash e o salt.
                    // Para simplificar, vou assumir que você tem um construtor que aceita todos os campos.
                    // Model::Usuario usuarioCarregado(id, username, passwordHash, salt);

                    // Vamos usar o construtor que você já tem. Adicionei "dummy_hash" como placeholder.
                    std::string dummy_hash = "hash_lido_do_arquivo"; // Substitua pela leitura real
                    Model::Usuario usuarioCarregado(id, username, dummy_hash, salt);

                    // Atualiza os outros campos que não estão no construtor
                    usuarioCarregado.setUltimoLoginTimestamp(ultimoLogin);
                    usuarios.push_back(usuarioCarregado);
                }

                arquivo.close();
                return usuarios;
            }
            bool registrarNovoUsuario(const std::string& username, const std::string& senha, Model::Usuario& outUsuario) {
                std::lock_guard<std::mutex> lock(mutexUsuarios);

                for (const auto& u : usuariosEmMemoria) {
                    if (u->getUsername() == username) {
                        return false;
                    }
                }

                uint32_t novoId = proximoIdDisponivel.fetch_add(1);
                std::string salt = CryptoUtils::gerarSalt();
                std::string hash = CryptoUtils::calcularHash(senha, salt);

                auto novoUsuario = std::make_shared<Model::Usuario>(novoId, username, hash, salt);
                usuariosEmMemoria.push_back(novoUsuario);
                salvarUsuario(*novoUsuario);

                outUsuario = *novoUsuario;
                return true;
            }

            bool autenticarUsuario(const std::string& username, const std::string& senha, Model::Usuario& outUsuario) {
                std::lock_guard<std::mutex> lock(mutexUsuarios);

                // Encontra o usuário pelo nome
                for (const auto& u : usuariosEmMemoria) {
                    if (u->getUsername() == username) {
                        // Calcula o hash da senha fornecida com o salt armazenado
                        std::string hashTentativa = CryptoUtils::calcularHash(senha, u->getSalt());

                        // Compara com o hash armazenado
                        if (u->verificarHashSenha(hashTentativa)) {
                            outUsuario = *u;
                            return true; // Sucesso
                        } else {
                            return false; // Senha incorreta
                        }
                    }
                }
                return false; // Usuário não encontrado
            }

            std::vector<std::shared_ptr<Model::Usuario>> getTodosUsuarios() {
                std::lock_guard<std::mutex> lock(mutexUsuarios);
                return usuariosEmMemoria;
            }
};

    }

} // fim do namespace Servidor


int main() {
    Servidor::Controller::ChatServidor meuServidor;
    meuServidor.iniciar(PORTA_SERVIDOR);

    return 0;
}