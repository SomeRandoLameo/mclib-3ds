#pragma once

#include <mclib/core/Client.h>
#include <mclib/protocol/packets/PacketHandler.h>

namespace example {

class ChatManager : public mc::protocol::packets::PacketHandler, public mc::core::ClientListener {
private:
    mc::core::Client* m_Client;

public:
    ChatManager(mc::core::Client* client, mc::protocol::packets::PacketDispatcher* dispatcher);
    ~ChatManager();

    void HandlePacket(mc::protocol::packets::in::ChatPacket* packet) override;

    void OnTick() override;
};

} // ns example
