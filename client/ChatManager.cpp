#include "ChatManager.h"

#include <mclib/util/Utility.h>

#include <iostream>


namespace example {

    ChatManager::ChatManager(mc::core::Client* client, mc::protocol::packets::PacketDispatcher* dispatcher)
            : mc::protocol::packets::PacketHandler(dispatcher), m_Client(client)
    {
        using namespace mc::protocol;

        m_Client->RegisterListener(this);
        dispatcher->RegisterHandler(State::Play, play::Chat, this);
    }

    ChatManager::~ChatManager() {
        GetDispatcher()->UnregisterHandler(this);
        m_Client->UnregisterListener(this);
    }

    void ChatManager::HandlePacket(mc::protocol::packets::in::ChatPacket* packet) {
        std::string message = mc::util::ParseChatNode(packet->GetChatData());

        if (!message.empty())
            std::cout << message << std::endl;

        //Custom Commands
        if (message.find("!selected") != std::string::npos) {
            mc::inventory::Slot item = m_Client->GetHotbar().GetCurrentItem();

            std::cout << "Selected item: " << item.GetItemId() << ":" << item.GetItemDamage() << " (" << (int)item.GetItemCount() << ")" << std::endl;
        } else if (message.find("!select") != std::string::npos) {
            std::string amountStr = message.substr(message.find("!select ") + 8);
            int slotIndex = strtol(amountStr.c_str(), nullptr, 10);


            if (slotIndex >= 0 && slotIndex < 9) {
                m_Client->GetHotbar().SelectSlot(slotIndex);
            } else {
                std::cout << "Bad slot index." << std::endl;
            }
        } else if (message.find("!find ") != std::string::npos) {
            std::string toFind = message.substr(message.find("!find ") + 6);

            s32 itemId = strtol(toFind.c_str(), nullptr, 10);
            mc::inventory::Inventory* inv = m_Client->GetInventoryManager()->GetPlayerInventory();
            if (inv) {
                bool contained = inv->Contains(itemId);

                std::cout << "Contains " << itemId << ": " << std::boolalpha << contained << std::endl;
            }
        } else if (message.find("!answer") != std::string::npos) {
            SwkbdState swkbd;
            char inputText[256] = {0};

            swkbdInit(&swkbd, SWKBD_TYPE_NORMAL, 2, -1);
            swkbdInputText(&swkbd, inputText, sizeof(inputText));

            mc::protocol::packets::out::ChatPacket packet(inputText);

            m_Client->GetConnection()->SendPacket(&packet);
        } else if (message.find("!getblock") != std::string::npos) {
            auto chunkpos = mc::Vector3i(0,0,0);
            auto blockpos = mc::Vector3i(0,3,0);

            auto readBlockPos = m_Client->GetWorld()->GetChunk(chunkpos)->GetBlock(blockpos);
            std::cout << "Block " << readBlockPos->GetName() << " : " << readBlockPos->GetType() << " in chunk " << to_string(chunkpos) <<" at pos "<< to_string(blockpos) << std::endl;

        }
    }

    void ChatManager::OnTick() {
        mc::core::PlayerPtr player = m_Client->GetPlayerManager()->GetPlayerByName(L"testplayer");
        if (!player) return;

        mc::entity::EntityPtr entity = player->GetEntity();
        if (!entity) return;
    }

} // ns example
