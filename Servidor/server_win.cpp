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
#include <random>
#include <filesystem>

#pragma comment(lib, "Ws2_32.lib")

#define PORTA_SERVIDOR 12345
#define TAMANHO_BUFFER 4096

namespace fs = std::filesystem;

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

    const unsigned int SHA256::sha256_k[64] =
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

#define SHA2_SHFR(x, n)    (x >> n)
#define SHA2_ROTR(x, n)   ((x >> n) | (x << ((sizeof(x) << 3) - n)))
#define SHA2_PACK32(str, x)                   \
    {                                         \
        *(x) =   ((uint32) *((str) + 3)      ) \
               | ((uint32) *((str) + 2) <<  8) \
               | ((uint32) *((str) + 1) << 16) \
               | ((uint32) *((str) + 0) << 24);   \
    }
#define SHA2_UNPACK32(x, str)                 \
    {                                         \
        *((str) + 3) = (uint8) ((x)      );   \
        *((str) + 2) = (uint8) ((x) >>  8);   \
        *((str) + 1) = (uint8) ((x) >> 16);   \
        *((str) + 0) = (uint8) ((x) >> 24);   \
    }
#define SHA256_F1(x) (SHA2_ROTR(x,  2) ^ SHA2_ROTR(x, 13) ^ SHA2_ROTR(x, 22))
#define SHA256_F2(x) (SHA2_ROTR(x,  6) ^ SHA2_ROTR(x, 11) ^ SHA2_ROTR(x, 25))
#define SHA256_F3(x) (SHA2_ROTR(x,  7) ^ SHA2_ROTR(x, 18) ^ SHA2_SHFR(x,  3))
#define SHA256_F4(x) (SHA2_ROTR(x, 17) ^ SHA2_ROTR(x, 19) ^ SHA2_SHFR(x, 10))
#define SHA2_CH(x, y, z)  ((x & y) ^ (~x & z))
#define SHA2_MAJ(x, y, z) ((x & y) ^ (x & z) ^ (y & z))

    void SHA256::init() {
        m_h[0] = 0x6a09e667; m_h[1] = 0xbb67ae85; m_h[2] = 0x3c6ef372; m_h[3] = 0xa54ff53a;
        m_h[4] = 0x510e527f; m_h[5] = 0x9b05688c; m_h[6] = 0x1f83d9ab; m_h[7] = 0x5be0cd19;
        m_len = 0; m_tot_len = 0;
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

    void SHA256::transform(const unsigned char* message, unsigned int block_nb) {
        uint32 w[64];
        uint32 wv[8];
        uint32 t1, t2;
        const unsigned char* sub_block;
        int i, j;
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
                wv[7] = wv[6]; wv[6] = wv[5]; wv[5] = wv[4];
                wv[4] = wv[3] + t1;
                wv[3] = wv[2]; wv[2] = wv[1]; wv[1] = wv[0];
                wv[0] = t1 + t2;
            }
            for (j = 0; j < 8; j++) {
                m_h[j] += wv[j];
            }
        }
    }

    void SHA256::final(unsigned char* digest) {
        unsigned int block_nb;
        unsigned int pm_len;
        unsigned int len_b;
        int i;
        block_nb = (1 + ((SHA224_256_BLOCK_SIZE - 9) < (m_len % SHA224_256_BLOCK_SIZE)));
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
        for (int i = 0; i < SHA256::DIGEST_SIZE; i++) {
            sprintf_s(buf + i * 2, 3, "%02x", digest[i]);
        }
        buf[2 * SHA256::DIGEST_SIZE] = 0;
        return std::string(buf);
    }

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
        Usuario(uint32_t id, const std::string& uname, const std::string& pHash, const std::string& s)
            : id(id), username(uname), passwordHash(pHash), salt(s), online(false), ultimoLoginTimestamp(0) {}

        Usuario(const Usuario& other)
            : id(other.id), username(other.username), passwordHash(other.passwordHash), salt(other.salt),
              online(other.online), ultimoLoginTimestamp(other.ultimoLoginTimestamp) {}


        uint32_t getId() const { return id; }
        const std::string& getUsername() const { return username; }
        const std::string& getSalt() const { return salt; }
        const std::string& getPasswordHash() const { return passwordHash; }
        bool isOnline() const { return online; }
        time_t getUltimoLoginTimestamp() const { return ultimoLoginTimestamp; }
        void setOnline(bool status) { this->online = status; }
        void setUltimoLoginTimestamp(time_t timestamp) { this->ultimoLoginTimestamp = timestamp; }
        bool verificarHashSenha(const std::string& hashSenhaFornecida) const { return this->passwordHash == hashSenhaFornecida; }
    };

    class Mensagem {
    };

}

namespace Persistencia {

    class GerenciadorUsuarios {
    private:
        const std::string nomeArquivo = "usuarios.dat";
        std::vector<std::shared_ptr<Model::Usuario>> usuariosEmMemoria;
        std::atomic<uint32_t> proximoIdDisponivel;
        std::mutex mutexUsuarios;

        void escreverString(std::ofstream& arquivo, const std::string& str) {
            size_t tamanho = str.size();
            arquivo.write(reinterpret_cast<const char*>(&tamanho), sizeof(tamanho));
            arquivo.write(str.c_str(), tamanho);
        }

        std::string lerString(std::ifstream& arquivo) {
            size_t tamanho = 0;
            arquivo.read(reinterpret_cast<char*>(&tamanho), sizeof(tamanho));
            if (arquivo.fail()) return "";
            std::string str(tamanho, '\0');
            arquivo.read(&str[0], tamanho);
            if (arquivo.fail()) return "";
            return str;
        }

        void reescreverArquivo() {
            std::ofstream arquivo(nomeArquivo, std::ios::binary | std::ios::trunc);
            if (!arquivo.is_open()) return;
            for (const auto& usuario : usuariosEmMemoria) {
                uint32_t id = usuario->getId();
                arquivo.write(reinterpret_cast<const char*>(&id), sizeof(id));
                escreverString(arquivo, usuario->getUsername());
                escreverString(arquivo, usuario->getPasswordHash());
                escreverString(arquivo, usuario->getSalt());
                time_t ultimoLogin = usuario->getUltimoLoginTimestamp();
                arquivo.write(reinterpret_cast<const char*>(&ultimoLogin), sizeof(ultimoLogin));
            }
        }

    public:
        GerenciadorUsuarios() : proximoIdDisponivel(1) {
            carregarUsuarios();
        }

        void carregarUsuarios() {
            std::lock_guard<std::mutex> lock(mutexUsuarios);
            std::ifstream arquivo(nomeArquivo, std::ios::binary);
            if (!arquivo.is_open()) {
                std::cout << "[PERSISTENCIA] Arquivo de usuarios '" << nomeArquivo << "' nao encontrado. Sera criado um novo." << std::endl;
                return;
            }
            usuariosEmMemoria.clear();
            uint32_t maxId = 0;
            while (arquivo.peek() != EOF) {
                uint32_t id;
                arquivo.read(reinterpret_cast<char*>(&id), sizeof(id));
                if (arquivo.eof()) break;
                std::string username = lerString(arquivo);
                std::string passwordHash = lerString(arquivo);
                std::string salt = lerString(arquivo);
                time_t ultimoLogin;
                arquivo.read(reinterpret_cast<char*>(&ultimoLogin), sizeof(ultimoLogin));
                if (arquivo.fail()) {
                    std::cerr << "[ERRO] Arquivo de usuarios corrompido. Parando o carregamento." << std::endl;
                    break;
                }
                auto usuarioCarregado = std::make_shared<Model::Usuario>(id, username, passwordHash, salt);
                usuarioCarregado->setUltimoLoginTimestamp(ultimoLogin);
                usuariosEmMemoria.push_back(usuarioCarregado);
                if (id > maxId) maxId = id;
            }
            proximoIdDisponivel = maxId + 1;
        }

        std::shared_ptr<Model::Usuario> findUserByUsername(const std::string& username) {
            std::lock_guard<std::mutex> lock(mutexUsuarios);
            for (const auto& u : usuariosEmMemoria) {
                if (u->getUsername() == username) {
                    return u;
                }
            }
            return nullptr;
        }

        std::shared_ptr<Model::Usuario> registrarNovoUsuario(const std::string& username, const std::string& senha) {
            std::lock_guard<std::mutex> lock(mutexUsuarios);
            if (findUserByUsername(username) != nullptr) {
                return nullptr;
            }
            uint32_t novoId = proximoIdDisponivel.fetch_add(1);
            std::string salt = CryptoUtils::gerarSalt();
            std::string hash = CryptoUtils::calcularHash(senha, salt);
            auto novoUsuario = std::make_shared<Model::Usuario>(novoId, username, hash, salt);
            usuariosEmMemoria.push_back(novoUsuario);
            reescreverArquivo();
            return novoUsuario;
        }

        std::shared_ptr<Model::Usuario> autenticarUsuario(const std::string& username, const std::string& senha) {
            std::lock_guard<std::mutex> lock(mutexUsuarios);
            for (const auto& u : usuariosEmMemoria) {
                if (u->getUsername() == username) {
                    std::string hashTentativa = CryptoUtils::calcularHash(senha, u->getSalt());
                    if (u->verificarHashSenha(hashTentativa)) {
                        return u;
                    }
                    return nullptr;
                }
            }
            return nullptr;
        }

        std::vector<std::shared_ptr<Model::Usuario>> getTodosUsuarios() {
            std::lock_guard<std::mutex> lock(mutexUsuarios);
            return usuariosEmMemoria;
        }
    };

}

namespace Controller {
    class ChatServidor;

    class TratadorCliente {
    private:
        SOCKET socketCliente;
        ChatServidor* instanciaServidor;
        Persistencia::GerenciadorUsuarios* gerenciadorUsuarios;
        std::shared_ptr<Model::Usuario> usuarioLogado;
        std::string bufferRecepcao;

        std::vector<std::string> parseMensagem(const std::string& msg);
        void handleLogin(const std::vector<std::string>& params);
        void handleRegistro(const std::vector<std::string>& params);
        void handleEnvioMensagem(const std::vector<std::string>& params);
        void handleTypingOn(const std::vector<std::string>& params);
        void handleTypingOff(const std::vector<std::string>& params);

    public:
        TratadorCliente(SOCKET socket, ChatServidor* servidor, Persistencia::GerenciadorUsuarios* gerenciador);
        ~TratadorCliente();
        uint32_t getUsuarioId() const;
        bool isLogado() const;

        void processarComunicacaoCliente();

        void enviarMensagemParaCliente(const std::string& msg);


    };

    class ChatServidor {
    private:
        SOCKET socketServidorOuvinte;
        sockaddr_in enderecoServidor;
        Persistencia::GerenciadorUsuarios gerenciadorUsuarios;
        std::map<uint32_t, TratadorCliente*> sessoesAtivas;
        std::mutex mutexSessoes;

        bool inicializarWinsock();
        bool criarSocketOuvinte();
        void configurarEnderecoServidor(int porta);
        bool vincularSocketOuvinte();
        bool iniciarEscuta();
        void limparRecursosWinsock();
        void fecharSocketOuvinte();

    public:
        ChatServidor();
        ~ChatServidor();

        void iniciar(int porta);
        void adicionarSessao(uint32_t userId, TratadorCliente* tratador);
        void removerSessao(uint32_t userId);
        bool isUsuarioOnline(uint32_t userId);

        Persistencia::GerenciadorUsuarios* getGerenciadorUsuarios() { return &gerenciadorUsuarios; }

        void encaminharMensagem(const std::string& remetente, const std::string& destinatarioUsername, const std::string& conteudo);

        void encaminharNotificacaoDigitando(const std::string& remetente, const std::string& destinatarioUsername, bool estaDigitando);

        void salvarMensagemOffline(uint32_t destinatarioId, const std::string& remetente, const std::string& conteudo, time_t timestamp) {
            fs::create_directories("mensagens_offline");

            std::string caminho = "mensagens_offline/" + std::to_string(destinatarioId) + ".msg";
            std::ofstream arquivo(caminho, std::ios::app);
            if (arquivo.is_open()) {
                arquivo << remetente << "|" << conteudo << "|" << timestamp << "\n";
                arquivo.close();
            } else {
                std::cerr << "[ERRO] Nao foi possivel salvar mensagem offline para o usuario ID " << destinatarioId << std::endl;
            }
        }

    };

    TratadorCliente::TratadorCliente(SOCKET socket, ChatServidor* servidor, Persistencia::GerenciadorUsuarios* gerenciador)
        : socketCliente(socket), instanciaServidor(servidor), gerenciadorUsuarios(gerenciador), usuarioLogado(nullptr) {}

    TratadorCliente::~TratadorCliente() {
        if (socketCliente != INVALID_SOCKET) {
            closesocket(socketCliente);
            socketCliente = INVALID_SOCKET;
        }
    }

    uint32_t TratadorCliente::getUsuarioId() const {
        return usuarioLogado ? usuarioLogado->getId() : 0;
    }

    bool TratadorCliente::isLogado() const {
        return usuarioLogado != nullptr;
    }

    std::vector<std::string> TratadorCliente::parseMensagem(const std::string& msg) {
        std::vector<std::string> partes;
        std::stringstream ss(msg);
        std::string parte;
        while (std::getline(ss, parte, '|')) {
            partes.push_back(parte);
        }
        return partes;
    }

    void TratadorCliente::enviarMensagemParaCliente(const std::string& msg) {
        if (socketCliente != INVALID_SOCKET) {
            send(socketCliente, msg.c_str(), static_cast<int>(msg.length()), 0);
        }
    }

    void TratadorCliente::handleLogin(const std::vector<std::string>& params) {
        if (params.size() < 3) return;

        auto usuarioPtr = gerenciadorUsuarios->autenticarUsuario(params[1], params[2]);
        if (usuarioPtr) {
            this->usuarioLogado = usuarioPtr;
            instanciaServidor->adicionarSessao(usuarioLogado->getId(), this);

            std::string listaContatosStr;
            auto todosUsuarios = gerenciadorUsuarios->getTodosUsuarios();
            for (const auto& u : todosUsuarios) {
                if (u->getId() == this->usuarioLogado->getId()) continue;
                listaContatosStr += u->getUsername() + "," + (instanciaServidor->isUsuarioOnline(u->getId()) ? "1" : "0") + ";";
            }
            if (!listaContatosStr.empty()) listaContatosStr.pop_back();

            std::string resposta = "LOGIN_OK|" + listaContatosStr + "\n";
            enviarMensagemParaCliente(resposta);
            std::cout << "[INFO] Usuario '" << usuarioLogado->getUsername() << "' logado com sucesso." << std::endl;
            uint32_t userId = usuarioLogado->getId();
            std::ifstream arqOffline("mensagens_offline/" + std::to_string(userId) + ".msg");
            if (arqOffline.is_open()) {
                std::string linha;
                while (std::getline(arqOffline, linha)) {
                    std::stringstream ss(linha);
                    std::string remetente, conteudo, timestamp;

                    std::getline(ss, remetente, '|');
                    std::getline(ss, conteudo, '|');
                    std::getline(ss, timestamp, '|');

                    std::string mensagem = "RECV_MSG|" + remetente + "|" + conteudo + "|" + timestamp + "\n";
                    enviarMensagemParaCliente(mensagem);
                }
                arqOffline.close();
                std::remove(("mensagens_offline/" + std::to_string(userId) + ".msg").c_str());
            }
        } else {
            std::string resposta = "LOGIN_FAIL|Usuario ou senha invalidos.\n";
            enviarMensagemParaCliente(resposta);
            std::cout << "[AVISO] Falha no login para o usuario '" << params[1] << "'." << std::endl;
        }
    }

    void TratadorCliente::handleRegistro(const std::vector<std::string>& params) {
        if (params.size() < 3) return;

        auto novoUsuarioPtr = gerenciadorUsuarios->registrarNovoUsuario(params[1], params[2]);
        if (novoUsuarioPtr) {
            enviarMensagemParaCliente("REG_OK\n");
            std::cout << "[INFO] Usuario '" << params[1] << "' registrado com sucesso." << std::endl;
        } else {
            enviarMensagemParaCliente("REG_FAIL|Usuario ja existe.\n");
        }
    }

    void TratadorCliente::handleEnvioMensagem(const std::vector<std::string>& params) {
        if (!isLogado() || params.size() < 3) return;
        instanciaServidor->encaminharMensagem(usuarioLogado->getUsername(), params[1], params[2]);
    }

    void TratadorCliente::handleTypingOn(const std::vector<std::string>& params) {
        if (!isLogado() || params.size() < 2) return;
        instanciaServidor->encaminharNotificacaoDigitando(usuarioLogado->getUsername(), params[1], true);
    }

    void TratadorCliente::handleTypingOff(const std::vector<std::string>& params) {
        if (!isLogado() || params.size() < 2) return;
        instanciaServidor->encaminharNotificacaoDigitando(usuarioLogado->getUsername(), params[1], false);
    }

    void TratadorCliente::processarComunicacaoCliente() {
        char buffer[TAMANHO_BUFFER];
        int bytesRecebidos;
        try {
            while ((bytesRecebidos = recv(socketCliente, buffer, TAMANHO_BUFFER, 0)) > 0) {
                bufferRecepcao.append(buffer, bytesRecebidos);
                size_t pos;
                while ((pos = bufferRecepcao.find('\n')) != std::string::npos) {
                    std::string mensagemCompleta = bufferRecepcao.substr(0, pos);
                    bufferRecepcao.erase(0, pos + 1);
                    if (mensagemCompleta.empty()) continue;

                    std::vector<std::string> partes = parseMensagem(mensagemCompleta);
                    if (partes.empty()) continue;

                    const std::string& comando = partes[0];
                    if (comando == "LOGIN") handleLogin(partes);
                    else if (comando == "REG") handleRegistro(partes);
                    else if (isLogado() && comando == "MSG") handleEnvioMensagem(partes);
                    else if (isLogado() && comando == "TYPING_ON") handleTypingOn(partes);
                    else if (isLogado() && comando == "TYPING_OFF") handleTypingOff(partes);
                    else if (!isLogado()) std::cerr << "[AVISO] Cliente tentou comando '" << comando << "' antes de logar." << std::endl;
                    else std::cerr << "[ERRO] Comando desconhecido: " << comando << std::endl;
                }
            }
        } catch (const std::exception& e) {
            std::cerr << "[EXCECAO] Excecao no tratador de cliente: " << e.what() << std::endl;
        }
    }

    ChatServidor::ChatServidor() : socketServidorOuvinte(INVALID_SOCKET) {}
    ChatServidor::~ChatServidor() {
        fecharSocketOuvinte();
        limparRecursosWinsock();
    }

    void ChatServidor::iniciar(int porta) {
        if (!inicializarWinsock()) return;
        if (!criarSocketOuvinte()) { limparRecursosWinsock(); return; }
        configurarEnderecoServidor(porta);
        if (!vincularSocketOuvinte()) { fecharSocketOuvinte(); limparRecursosWinsock(); return; }
        if (!iniciarEscuta()) { fecharSocketOuvinte(); limparRecursosWinsock(); return; }

        std::cout << "[INFO] Servidor de Chat iniciado na porta " << porta << std::endl;
        while (true) {
            SOCKET socketNovoCliente = accept(socketServidorOuvinte, nullptr, nullptr);
            if (socketNovoCliente == INVALID_SOCKET) {
                std::cerr << "[ERRO] accept falhou com erro: " << WSAGetLastError() << std::endl;
                continue;
            }
            std::cout << "[INFO] Nova conexao aceita. Socket: " << socketNovoCliente << std::endl;

            std::thread([this, socketNovoCliente]() {
                auto* tratador = new TratadorCliente(socketNovoCliente, this, getGerenciadorUsuarios());
                tratador->processarComunicacaoCliente();

                if (tratador->isLogado()) {
                    this->removerSessao(tratador->getUsuarioId());
                }
                std::cout << "[INFO] Conexao encerrada. socket: " << socketNovoCliente << std::endl;
                delete tratador;
            }).detach();
        }
    }

    void ChatServidor::encaminharMensagem(const std::string& remetente, const std::string& destinatarioUsername, const std::string& conteudo) {
        auto destinatarioUserObj = gerenciadorUsuarios.findUserByUsername(destinatarioUsername);
        if (!destinatarioUserObj) {
            std::cout << "[AVISO] Tentativa de enviar mensagem para usuario inexistente: " << destinatarioUsername << std::endl;
            return;
        }
        uint32_t destinatarioId = destinatarioUserObj->getId();
        std::lock_guard<std::mutex> lock(mutexSessoes);
        auto it = sessoesAtivas.find(destinatarioId);
        if (it != sessoesAtivas.end()) {
            TratadorCliente* tratadorDestino = it->second;
            time_t timestamp = time(0);
            std::string msgParaEnviar = "RECV_MSG|" + remetente + "|" + conteudo + "|" + std::to_string(timestamp) + "\n";
            tratadorDestino->enviarMensagemParaCliente(msgParaEnviar);
            std::cout << "[MSG] Mensagem de '" << remetente << "' para '" << destinatarioUsername << "' encaminhada com sucesso." << std::endl;
        } else {
            std::cout << "[MSG] Usuario '" << destinatarioUsername << "' esta offline. Salvando mensagem..." << std::endl;
            time_t timestamp = time(0);
            salvarMensagemOffline(destinatarioId, remetente, conteudo, timestamp);
        }
    }

    void ChatServidor::adicionarSessao(uint32_t userId, TratadorCliente* tratador) {
        std::lock_guard<std::mutex> lock(mutexSessoes);
        sessoesAtivas[userId] = tratador;
    }

    void ChatServidor::removerSessao(uint32_t userId) {
        std::lock_guard<std::mutex> lock(mutexSessoes);
        if(sessoesAtivas.count(userId)) {
            sessoesAtivas.erase(userId);
            std::cout << "[INFO] Sessao removida para o usuario ID: " << userId << std::endl;
        }
    }

    bool ChatServidor::isUsuarioOnline(uint32_t userId) {
        std::lock_guard<std::mutex> lock(mutexSessoes);
        return sessoesAtivas.count(userId) > 0;
    }

    bool ChatServidor::inicializarWinsock() {
        WSADATA wsaData;
        int resultado = WSAStartup(MAKEWORD(2, 2), &wsaData);
        if (resultado != 0) {
            std::cerr << "[ERRO] WSAStartup falhou: " << resultado << std::endl;
            return false;
        }
        return true;
    }

    bool ChatServidor::criarSocketOuvinte() {
        socketServidorOuvinte = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (socketServidorOuvinte == INVALID_SOCKET) {
            std::cerr << "[ERRO] Criacao do socket falhou: " << WSAGetLastError() << std::endl;
            return false;
        }
        return true;
    }

    void ChatServidor::configurarEnderecoServidor(int porta) {
        enderecoServidor.sin_family = AF_INET;
        enderecoServidor.sin_addr.s_addr = INADDR_ANY;
        enderecoServidor.sin_port = htons(porta);
    }

    bool ChatServidor::vincularSocketOuvinte() {
        if (bind(socketServidorOuvinte, (sockaddr*)&enderecoServidor, sizeof(enderecoServidor)) == SOCKET_ERROR) {
            std::cerr << "[ERRO] Bind falhou: " << WSAGetLastError() << std::endl;
            return false;
        }
        return true;
    }

    bool ChatServidor::iniciarEscuta() {
        if (listen(socketServidorOuvinte, SOMAXCONN) == SOCKET_ERROR) {
            std::cerr << "[ERRO] Listen falhou: " << WSAGetLastError() << std::endl;
            return false;
        }
        return true;
    }

    void ChatServidor::limparRecursosWinsock() {
        WSACleanup();
    }

    void ChatServidor::fecharSocketOuvinte() {
        if (socketServidorOuvinte != INVALID_SOCKET) {
            closesocket(socketServidorOuvinte);
            socketServidorOuvinte = INVALID_SOCKET;
        }
    }
    void ChatServidor::encaminharNotificacaoDigitando(const std::string& remetente, const std::string& destinatarioUsername, bool estaDigitando) {
        auto destinatarioUserObj = gerenciadorUsuarios.findUserByUsername(destinatarioUsername);
        if (!destinatarioUserObj) return;

        uint32_t destinatarioId = destinatarioUserObj->getId();
        std::lock_guard<std::mutex> lock(mutexSessoes);
        auto it = sessoesAtivas.find(destinatarioId);
        if (it != sessoesAtivas.end()) {
            TratadorCliente* tratadorDestino = it->second;
            std::string comando = estaDigitando ? "TYPING_ON_NOTIFY|" : "TYPING_OFF_NOTIFY|";
            std::string msgParaEnviar = comando + remetente + "\n";
            tratadorDestino->enviarMensagemParaCliente(msgParaEnviar);
        }
    }

}
}

int main() {
    SetConsoleOutputCP(CP_UTF8);
    Servidor::Controller::ChatServidor meuServidor;
    meuServidor.iniciar(PORTA_SERVIDOR);
    return 0;
}