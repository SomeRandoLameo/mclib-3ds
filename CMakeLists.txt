cmake_minimum_required(VERSION 4.0)

project(mclib)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED true)

add_library(mclib STATIC
    mclib/src/mclib/block/Banner.cpp
    mclib/src/mclib/block/Beacon.cpp
    mclib/src/mclib/block/Bed.cpp
    mclib/src/mclib/block/Block.cpp
    mclib/src/mclib/block/BlockEntity.cpp
    mclib/src/mclib/block/BrewingStand.cpp
    mclib/src/mclib/block/Chest.cpp
    mclib/src/mclib/block/Dispenser.cpp
    mclib/src/mclib/block/Dropper.cpp
    mclib/src/mclib/block/EnchantmentTable.cpp
    mclib/src/mclib/block/EndGateway.cpp
    mclib/src/mclib/block/FlowerPot.cpp
    mclib/src/mclib/block/Furnace.cpp
    mclib/src/mclib/block/Hopper.cpp
    mclib/src/mclib/block/InventoryBlock.cpp
    mclib/src/mclib/block/Jukebox.cpp
    mclib/src/mclib/block/MonsterSpawner.cpp
    mclib/src/mclib/block/NoteBlock.cpp
    mclib/src/mclib/block/Piston.cpp
    mclib/src/mclib/block/RedstoneComparator.cpp
    mclib/src/mclib/block/ShulkerBox.cpp
    mclib/src/mclib/block/Sign.cpp
    mclib/src/mclib/block/Skull.cpp
    mclib/src/mclib/common/DataBuffer.cpp
    mclib/src/mclib/common/DyeColor.cpp
    mclib/src/mclib/common/MCString.cpp
    mclib/src/mclib/common/Position.cpp
    mclib/src/mclib/common/UUID.cpp
    mclib/src/mclib/common/VarInt.cpp
    mclib/src/mclib/core/AuthToken.cpp
    mclib/src/mclib/core/Client.cpp
    mclib/src/mclib/core/ClientSettings.cpp
    mclib/src/mclib/core/Compression.cpp
    mclib/src/mclib/core/Connection.cpp
    mclib/src/mclib/core/Encryption.cpp
    mclib/src/mclib/core/PlayerManager.cpp
    mclib/src/mclib/entity/EntityManager.cpp
    mclib/src/mclib/entity/Metadata.cpp
    mclib/src/mclib/inventory/Hotbar.cpp
    mclib/src/mclib/inventory/Inventory.cpp
    mclib/src/mclib/inventory/Slot.cpp
    mclib/src/mclib/nbt/NBT.cpp
    mclib/src/mclib/nbt/Tag.cpp
    mclib/src/mclib/network/IPAddress.cpp
    mclib/src/mclib/network/Network.cpp
    mclib/src/mclib/network/Socket.cpp
    mclib/src/mclib/network/TCPSocket.cpp
    mclib/src/mclib/network/UDPSocket.cpp
    mclib/src/mclib/protocol/packets/Packet.cpp
    mclib/src/mclib/protocol/packets/PacketDispatcher.cpp
    mclib/src/mclib/protocol/packets/PacketFactory.cpp
    mclib/src/mclib/protocol/packets/PacketHandler.cpp
    mclib/src/mclib/protocol/Protocol.cpp
    mclib/src/mclib/util/Forge.cpp
    mclib/src/mclib/util/Hash.cpp
    mclib/src/mclib/util/HTTPClient.cpp
    mclib/src/mclib/util/Utility.cpp
    mclib/src/mclib/util/VersionFetcher.cpp
    mclib/src/mclib/util/Yggdrasil.cpp
    mclib/src/mclib/world/Chunk.cpp
    mclib/src/mclib/world/World.cpp
)

add_definitions(-DMCLIB_EXPORTS -DCURL_STATICLIB)

set_target_properties(mclib PROPERTIES VERSION 1.0.0)
set_target_properties(mclib PROPERTIES SOVERSION 1)

target_include_directories(mclib
    PUBLIC
    mclib/include
    mclib/include/mclib/core
    mclib/include/mclib/common
    mclib/include/mclib/util
    PRIVATE
    ${DEVKITPRO}/portlibs/3ds/include
)

target_link_libraries(mclib z curl mbedtls mbedx509 mbedcrypto)

target_compile_options(mclib PUBLIC
    -Wno-changes-meaning
)

install(TARGETS mclib)
install(DIRECTORY mclib/include DESTINATION include)

configure_file(mclib.pc.in mclib.pc @ONLY)
install(FILES ${CMAKE_BINARY_DIR}/mclib.pc DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/pkgconfig)


#
# --- 3DS Client Build Target ---
#

set(CLIENT_NAME "mclib-client")
set(CLIENT_DESC "Test client using mclib")
set(CLIENT_AUTHOR "SomeRandoLameo")
set(CLIENT_ICON "${CMAKE_SOURCE_DIR}/icon.png")
set(CLIENT_ROMFS "${CMAKE_SOURCE_DIR}/romfs")


file(GLOB CLIENT_SRC
        "${CMAKE_SOURCE_DIR}/client/*.cpp"
)


add_executable(${CLIENT_NAME}
        ${CLIENT_SRC}
)


target_include_directories(${CLIENT_NAME} PUBLIC
        client
        mclib/include
        ${DEVKITPRO}/portlibs/3ds/include
)


target_link_libraries(${CLIENT_NAME} PUBLIC
        mclib
        ctru
        citro3d
        z
        m
)


target_compile_options(${CLIENT_NAME} PUBLIC
        -Wno-changes-meaning
)

# --- 3DSX Metadata & Build ---
ctr_generate_smdh(
        ${CMAKE_BINARY_DIR}/${CLIENT_NAME}.smdh
        NAME "${CLIENT_NAME}"
        DESCRIPTION "${CLIENT_DESC}"
        AUTHOR "${CLIENT_AUTHOR}"
        ICON "${CLIENT_ICON}"
)

ctr_create_3dsx(
        ${CLIENT_NAME}
        OUTPUT "${CMAKE_BINARY_DIR}/${CLIENT_NAME}.3dsx"
        SMDH "${CMAKE_BINARY_DIR}/${CLIENT_NAME}.smdh"
        ROMFS "${CLIENT_ROMFS}"
)

# "Send" Target (3dslink)
add_custom_target(
        send-client
        COMMAND 3dslink -a "${3DS_IP}" "${CMAKE_BINARY_DIR}/${CLIENT_NAME}.3dsx"
        COMMENT "Sending client to 3DS..."
)

message(STATUS "3DS Client target '${CLIENT_NAME}' enabled. ")

