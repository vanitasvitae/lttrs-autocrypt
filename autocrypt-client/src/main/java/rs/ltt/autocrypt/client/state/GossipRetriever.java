package rs.ltt.autocrypt.client.state;

import rs.ltt.autocrypt.client.header.AutocryptHeader;

public interface GossipRetriever {

    void onAutocryptGossipHeader(final AutocryptHeader autocryptHeader);
}
