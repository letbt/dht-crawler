
cd ../
RELEASE_VERSION="1.0.0"

if [[ $CURRENT_OS == "MacOS" ]]; then
    cargo build

    CONF_DIR="$INSTALL_DIR/conf"

    mkdir -p $CONF_DIR
    cp target/debug/dht-crawler $INSTALL_DIR
    cp conf/* $CONF_DIR
elif [[ $CURRENT_OS == "Linux" ]] && command -v dpkg-deb &> /dev/null; then

    cargo build --release

    RELEASE_NAME="crawler"
    
    DEBIAN_CONTROL="\
Package: ${RELEASE_NAME} \n\
Version: ${RELEASE_VERSION} \n\
Section: base \n\
Priority: optional \n\
Architecture: amd64 \n\
Description: DHT Crawler\n\
Maintainer: letbt.net\n\
    "
    DEB_BUILD_ROOT="${INSTALL_DIR}/${RELEASE_NAME}-${RELEASE_VERSION}"

    rm -rf ${DEB_BUILD_ROOT}
    mkdir -p ${DEB_BUILD_ROOT}/DEBIAN
    mkdir -p ${DEB_BUILD_ROOT}/etc/crawler/
    mkdir -p ${DEB_BUILD_ROOT}/usr/local/sbin/
    mkdir -p ${DEB_BUILD_ROOT}/var/log/crawler/
    mkdir -p ${DEB_BUILD_ROOT}/etc/systemd/system/

    echo -e "\
blacklist = 10000\n\
port = 6881\n\
bootstrap_nodes = [\n\t\"bttracker.debian.org:6881\", \n\t\"dht.libtorrent.org:25401\"\n]\n\
limit = 10\n\
url = \"\"\n\
    " > ${DEB_BUILD_ROOT}/etc/crawler/crawler.toml

    echo -e ${DEBIAN_CONTROL} > ${DEB_BUILD_ROOT}/DEBIAN/control
    echo -e "systemctl daemon-reload" > ${DEB_BUILD_ROOT}/DEBIAN/postinst
    echo -e "systemctl daemon-reload" > ${DEB_BUILD_ROOT}/DEBIAN/postrm
    chmod 755 ${DEB_BUILD_ROOT}/DEBIAN/postinst
    chmod 755 ${DEB_BUILD_ROOT}/DEBIAN/postrm

    cp target/release/dht-crawler ${DEB_BUILD_ROOT}/usr/local/sbin/

    cd ${CWD}
    
    cp debian/crawler.service ${DEB_BUILD_ROOT}/etc/systemd/system/

    dpkg-deb --root-owner-group --build ${DEB_BUILD_ROOT}

fi