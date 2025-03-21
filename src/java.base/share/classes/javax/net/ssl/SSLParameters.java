/*
 * Copyright (c) 2005, 2025, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

package javax.net.ssl;

import java.security.AlgorithmConstraints;
import java.util.*;

/**
 * Encapsulates parameters for an SSL/TLS/DTLS connection. The parameters
 * are the list of ciphersuites to be accepted in an SSL/TLS/DTLS handshake,
 * the list of protocols to be allowed, the endpoint identification
 * algorithm during SSL/TLS/DTLS handshaking, the Server Name Indication (SNI),
 * the maximum network packet size, the algorithm constraints, the signature
 * schemes, the key exchange named groups and whether SSL/TLS/DTLS servers
 * should request or require client authentication, etc.
 * <p>
 * {@code SSLParameter} objects can be created via the constructors in this
 * class, and can be described as pre-populated objects. {@code SSLParameter}
 * objects can also be obtained using the {@code getSSLParameters()} methods in
 * {@link SSLSocket#getSSLParameters SSLSocket} and
 * {@link SSLServerSocket#getSSLParameters SSLServerSocket} and
 * {@link SSLEngine#getSSLParameters SSLEngine} or the
 * {@link SSLContext#getDefaultSSLParameters getDefaultSSLParameters()} and
 * {@link SSLContext#getSupportedSSLParameters getSupportedSSLParameters()}
 * methods in {@code SSLContext}, and can be described as connection populated
 * objects.
 * <p>
 * SSLParameters can be applied to a connection via the methods
 * {@link SSLSocket#setSSLParameters SSLSocket.setSSLParameters()} and
 * {@link SSLServerSocket#setSSLParameters SSLServerSocket.setSSLParameters()}
 * and {@link SSLEngine#setSSLParameters SSLEngine.setSSLParameters()}.
 * <p>
 * For example:
 *
 * <blockquote><pre>
 *     SSLParameters p = sslSocket.getSSLParameters();
 *     p.setProtocols(new String[] { "TLSv1.2" });
 *     p.setCipherSuites(
 *         new String[] { "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", ... });
 *     p.setApplicationProtocols(new String[] {"h2", "http/1.1"});
 *     sslSocket.setSSLParameters(p);
 * </pre></blockquote>
 *
 * @see SSLSocket
 * @see SSLEngine
 * @see SSLContext
 *
 * @since 1.6
 */
public class SSLParameters {

    private String[] cipherSuites;
    private String[] protocols;
    private boolean wantClientAuth;
    private boolean needClientAuth;
    private String identificationAlgorithm;
    private AlgorithmConstraints algorithmConstraints;
    private List<SNIServerName> sniNames = null;        // immutable list
    private Collection<SNIMatcher> sniMatchers = null;  // immutable collection
    private boolean preferLocalCipherSuites;
    private boolean enableRetransmissions = true;
    private int maximumPacketSize = 0;
    private String[] applicationProtocols = new String[0];
    private String[] signatureSchemes = null;
    private String[] namedGroups = null;

    /**
     * Constructs SSLParameters.
     * <p>
     * The values of cipherSuites, protocols, cryptographic algorithm
     * constraints, endpoint identification algorithm, signature schemes,
     * server names and server name matchers are set to {@code null};
     * useCipherSuitesOrder, wantClientAuth and needClientAuth are set
     * to {@code false}; enableRetransmissions is set to {@code true};
     * maximum network packet size is set to {@code 0}.
     */
    public SSLParameters() {
        // empty
    }

    /**
     * Constructs SSLParameters from the specified array of ciphersuites.
     * <p>
     * Calling this constructor is equivalent to calling the no-args
     * constructor followed by
     * {@code setCipherSuites(cipherSuites);}.  Note that the
     * standard list of cipher suite names may be found in the <a href=
     * "{@docRoot}/../specs/security/standard-names.html#jsse-cipher-suite-names">
     * JSSE Cipher Suite Names</a> section of the Java Security Standard
     * Algorithm Names Specification.  Providers may support cipher suite
     * names not found in this list.
     *
     * @spec security/standard-names.html Java Security Standard Algorithm Names
     * @param cipherSuites the array of ciphersuites (or null)
     */
    @SuppressWarnings("this-escape")
    public SSLParameters(String[] cipherSuites) {
        setCipherSuites(cipherSuites);
    }

    /**
     * Constructs SSLParameters from the specified array of ciphersuites
     * and protocols.
     * <p>
     * Calling this constructor is equivalent to calling the no-args
     * constructor followed by
     * {@code setCipherSuites(cipherSuites); setProtocols(protocols);}.
     * Note that the standard list of cipher suite names may be found in the
     * <a href=
     * "{@docRoot}/../specs/security/standard-names.html#jsse-cipher-suite-names">
     * JSSE Cipher Suite Names</a> section of the Java Security Standard
     * Algorithm Names Specification.  Providers may support cipher suite
     * names not found in this list.
     *
     * @spec security/standard-names.html Java Security Standard Algorithm Names
     * @param cipherSuites the array of ciphersuites (or null)
     * @param protocols the array of protocols (or null)
     */
    @SuppressWarnings("this-escape")
    public SSLParameters(String[] cipherSuites, String[] protocols) {
        setCipherSuites(cipherSuites);
        setProtocols(protocols);
    }

    private static String[] clone(String[] s) {
        return (s == null) ? null : s.clone();
    }

    /**
     * Returns a copy of the array of ciphersuites or null if none
     * have been set.
     * <P>
     * The returned array includes cipher suites from the list of standard
     * cipher suite names in the <a href=
     * "{@docRoot}/../specs/security/standard-names.html#jsse-cipher-suite-names">
     * JSSE Cipher Suite Names</a> section of the Java Security Standard
     * Algorithm Names Specification, and may also include other cipher suites
     * that the provider supports.
     *
     * @spec security/standard-names.html Java Security Standard Algorithm Names
     * @return a copy of the array of ciphersuites or null if none
     * have been set.
     */
    public String[] getCipherSuites() {
        return clone(cipherSuites);
    }

    /**
     * Sets the array of ciphersuites.
     *
     * @param cipherSuites the array of ciphersuites (or null).  Note that the
     * standard list of cipher suite names may be found in the <a href=
     * "{@docRoot}/../specs/security/standard-names.html#jsse-cipher-suite-names">
     * JSSE Cipher Suite Names</a> section of the Java Security Standard
     * Algorithm Names Specification.  Providers may support cipher suite
     * names not found in this list or might not use the recommended name
     * for a certain cipher suite.
     * @spec security/standard-names.html Java Security Standard Algorithm Names
     */
    public void setCipherSuites(String[] cipherSuites) {
        this.cipherSuites = clone(cipherSuites);
    }

    /**
     * Returns a copy of the array of protocols or null if none
     * have been set.
     *
     * @return a copy of the array of protocols or null if none
     * have been set.
     */
    public String[] getProtocols() {
        return clone(protocols);
    }

    /**
     * Sets the array of protocols.
     *
     * @param protocols the array of protocols (or null)
     */
    public void setProtocols(String[] protocols) {
        this.protocols = clone(protocols);
    }

    /**
     * Returns whether client authentication should be requested.
     *
     * @return whether client authentication should be requested.
     */
    public boolean getWantClientAuth() {
        return wantClientAuth;
    }

    /**
     * Sets whether client authentication should be requested. Calling
     * this method clears the {@code needClientAuth} flag.
     *
     * @param wantClientAuth whether client authentication should be requested
     */
    public void setWantClientAuth(boolean wantClientAuth) {
        this.wantClientAuth = wantClientAuth;
        this.needClientAuth = false;
    }

    /**
     * Returns whether client authentication should be required.
     *
     * @return whether client authentication should be required.
     */
    public boolean getNeedClientAuth() {
        return needClientAuth;
    }

    /**
     * Sets whether client authentication should be required. Calling
     * this method clears the {@code wantClientAuth} flag.
     *
     * @param needClientAuth whether client authentication should be required
     */
    public void setNeedClientAuth(boolean needClientAuth) {
        this.wantClientAuth = false;
        this.needClientAuth = needClientAuth;
    }

    /**
     * Returns the cryptographic algorithm constraints.
     *
     * @return the cryptographic algorithm constraints, or null if the
     *     constraints have not been set
     *
     * @see #setAlgorithmConstraints(AlgorithmConstraints)
     *
     * @since 1.7
     */
    public AlgorithmConstraints getAlgorithmConstraints() {
        return algorithmConstraints;
    }

    /**
     * Sets the cryptographic algorithm constraints, which will be used
     * in addition to any configured by the runtime environment.
     * <p>
     * If the {@code constraints} parameter is non-null, every
     * cryptographic algorithm, key and algorithm parameters used in the
     * SSL/TLS/DTLS handshake must be permitted by the constraints.
     *
     * @param constraints the algorithm constraints (or null)
     *
     * @since 1.7
     */
    public void setAlgorithmConstraints(AlgorithmConstraints constraints) {
        // the constraints object is immutable
        this.algorithmConstraints = constraints;
    }

    /**
     * Gets the endpoint identification algorithm.
     *
     * @return the endpoint identification algorithm, or null if none
     * has been set.
     *
     * @see X509ExtendedTrustManager
     * @see #setEndpointIdentificationAlgorithm(String)
     *
     * @since 1.7
     */
    public String getEndpointIdentificationAlgorithm() {
        return identificationAlgorithm;
    }

    /**
     * Sets the endpoint identification algorithm.
     * <p>
     * If the {@code algorithm} parameter is non-null or non-empty, the
     * endpoint identification/verification procedures must be handled during
     * SSL/TLS/DTLS handshaking.  This is to prevent man-in-the-middle attacks.
     *
     * @param algorithm The standard string name of the endpoint
     *     identification algorithm (or null).
     *     See the <a href=
     *     "{@docRoot}/../specs/security/standard-names.html">
     *     Java Security Standard Algorithm Names</a> document
     *     for information about standard algorithm names.
     *
     * @spec security/standard-names.html Java Security Standard Algorithm Names
     * @see X509ExtendedTrustManager
     *
     * @since 1.7
     */
    public void setEndpointIdentificationAlgorithm(String algorithm) {
        this.identificationAlgorithm = algorithm;
    }

    /**
     * Sets the desired {@link SNIServerName}s of the Server Name
     * Indication (SNI) parameter.
     * <P>
     * This method is only useful to {@link SSLSocket}s or {@link SSLEngine}s
     * operating in client mode.
     * <P>
     * Note that the {@code serverNames} list is cloned
     * to protect against subsequent modification.
     *
     * @param  serverNames
     *         the list of desired {@link SNIServerName}s (or null)
     *
     * @throws NullPointerException if the {@code serverNames}
     *         contains {@code null} element
     * @throws IllegalArgumentException if the {@code serverNames}
     *         contains more than one name of the same name type
     *
     * @see SNIServerName
     * @see #getServerNames()
     *
     * @since 1.8
     */
    public final void setServerNames(List<SNIServerName> serverNames) {
        if (this.sniNames == serverNames) {
            return;
        }

        if (serverNames == null) {
            sniNames = null;
        } else if (serverNames.isEmpty()) {
            sniNames = Collections.emptyList();
        } else {
            List<Integer> sniTypes = new ArrayList<>(serverNames.size());
            List<SNIServerName> sniValues = new ArrayList<>(serverNames.size());
            for (SNIServerName serverName : serverNames) {
                if (sniTypes.contains(serverName.getType())) {
                    throw new IllegalArgumentException(
                            "Duplicated server name of type " +
                                    serverName.getType());
                } else {
                    sniTypes.add(serverName.getType());
                    sniValues.add(serverName);
                }
            }

            sniNames = Collections.unmodifiableList(sniValues);
        }
    }

    /**
     * Returns a {@link List} containing all {@link SNIServerName}s of the
     * Server Name Indication (SNI) parameter, or null if none has been set.
     * <P>
     * This method is only useful to {@link SSLSocket}s or {@link SSLEngine}s
     * operating in client mode.
     * <P>
     * For SSL/TLS/DTLS connections, the underlying SSL/TLS/DTLS provider
     * may specify a default value for a certain server name type.  In
     * client mode, it is recommended that, by default, providers should
     * include the server name indication whenever the server can be located
     * by a supported server name type.
     * <P>
     * It is recommended that providers initialize default Server Name
     * Indications when creating {@code SSLSocket}/{@code SSLEngine}s.
     * In the following examples, the server name may be represented by an
     * instance of {@link SNIHostName} which has been initialized with the
     * hostname "www.example.com" and type
     * {@link StandardConstants#SNI_HOST_NAME}.
     *
     * <pre>
     *     Socket socket =
     *         sslSocketFactory.createSocket("www.example.com", 443);
     * </pre>
     * or
     * <pre>
     *     SSLEngine engine =
     *         sslContext.createSSLEngine("www.example.com", 443);
     * </pre>
     *
     * @return null or an immutable list of non-null {@link SNIServerName}s
     *
     * @see List
     * @see #setServerNames(List)
     *
     * @since 1.8
     */
    public final List<SNIServerName> getServerNames() {
        return sniNames;
    }

    /**
     * Sets the {@link SNIMatcher}s of the Server Name Indication (SNI)
     * parameter.
     * <P>
     * This method is only useful to {@link SSLSocket}s or {@link SSLEngine}s
     * operating in server mode.
     * <P>
     * Note that the {@code matchers} collection is cloned to protect
     * against subsequent modification.
     *
     * @param  matchers
     *         the collection of {@link SNIMatcher}s (or null)
     *
     * @throws NullPointerException if the {@code matchers}
     *         contains {@code null} element
     * @throws IllegalArgumentException if the {@code matchers}
     *         contains more than one name of the same name type
     *
     * @see Collection
     * @see SNIMatcher
     * @see #getSNIMatchers()
     *
     * @since 1.8
     */
    public final void setSNIMatchers(Collection<SNIMatcher> matchers) {
        if (this.sniMatchers == matchers) {
            return;
        }

        if (matchers == null) {
            this.sniMatchers = null;
        } else if (matchers.isEmpty()) {
            sniMatchers = Collections.emptyList();
        } else {
            List<Integer> matcherTypes = new ArrayList<>(matchers.size());
            List<SNIMatcher> matcherValues = new ArrayList<>(matchers.size());
            for (SNIMatcher matcher : matchers) {
                if (matcherTypes.contains(matcher.getType())) {
                    throw new IllegalArgumentException(
                                "Duplicated server name of type " +
                                matcher.getType());
                } else {
                    matcherTypes.add(matcher.getType());
                    matcherValues.add(matcher);
                }
            }

            this.sniMatchers = Collections.unmodifiableList(matcherValues);
        }
    }

    /**
     * Returns a {@link Collection} containing all {@link SNIMatcher}s of the
     * Server Name Indication (SNI) parameter, or null if none has been set.
     * <P>
     * This method is only useful to {@link SSLSocket}s or {@link SSLEngine}s
     * operating in server mode.
     * <P>
     * For better interoperability, providers generally will not define
     * default matchers so that by default servers will ignore the SNI
     * extension and continue the handshake.
     *
     * @return null or an immutable collection of non-null {@link SNIMatcher}s
     *
     * @see SNIMatcher
     * @see #setSNIMatchers(Collection)
     *
     * @since 1.8
     */
    public final Collection<SNIMatcher> getSNIMatchers() {
        return sniMatchers;
    }

    /**
     * Sets whether the local cipher suites preference should be honored.
     *
     * @param honorOrder whether local cipher suites order in
     *        {@code #getCipherSuites} should be honored during
     *        SSL/TLS/DTLS handshaking.
     *
     * @see #getUseCipherSuitesOrder()
     *
     * @since 1.8
     */
    public final void setUseCipherSuitesOrder(boolean honorOrder) {
        this.preferLocalCipherSuites = honorOrder;
    }

    /**
     * Returns whether the local cipher suites preference should be honored.
     *
     * @return whether local cipher suites order in {@code #getCipherSuites}
     *         should be honored during SSL/TLS/DTLS handshaking.
     *
     * @see #setUseCipherSuitesOrder(boolean)
     *
     * @since 1.8
     */
    public final boolean getUseCipherSuitesOrder() {
        return preferLocalCipherSuites;
    }

    /**
     * Sets whether DTLS handshake retransmissions should be enabled.
     *
     * This method only applies to DTLS.
     *
     * @param   enableRetransmissions
     *          {@code true} indicates that DTLS handshake retransmissions
     *          should be enabled; {@code false} indicates that DTLS handshake
     *          retransmissions should be disabled
     *
     * @see     #getEnableRetransmissions()
     *
     * @since 9
     */
    public void setEnableRetransmissions(boolean enableRetransmissions) {
        this.enableRetransmissions = enableRetransmissions;
    }

    /**
     * Returns whether DTLS handshake retransmissions should be enabled.
     *
     * This method only applies to DTLS.
     *
     * @return  true, if DTLS handshake retransmissions should be enabled
     *
     * @see     #setEnableRetransmissions(boolean)
     *
     * @since 9
     */
    public boolean getEnableRetransmissions() {
        return enableRetransmissions;
    }

    /**
     * Sets the maximum expected network packet size in bytes for
     * SSL/TLS/DTLS records.
     *
     * @apiNote  It is recommended that if possible, the maximum packet size
     *           should not be less than 256 bytes so that small handshake
     *           messages, such as HelloVerifyRequests, are not fragmented.
     *
     * @implNote If the maximum packet size is too small to hold a minimal
     *           record, an implementation may attempt to generate as minimal
     *           records as possible.  However, this may cause a generated
     *           packet to be larger than the maximum packet size.
     *
     * @param   maximumPacketSize
     *          the maximum expected network packet size in bytes, or
     *          {@code 0} to use the implicit size that is automatically
     *          specified by the underlying implementation.
     * @throws  IllegalArgumentException
     *          if {@code maximumPacketSize} is negative.
     *
     * @see     #getMaximumPacketSize()
     *
     * @since 9
     */
    public void setMaximumPacketSize(int maximumPacketSize) {
        if (maximumPacketSize < 0) {
            throw new IllegalArgumentException(
                "The maximum packet size cannot be negative");
        }

        this.maximumPacketSize = maximumPacketSize;
    }

    /**
     * Returns the maximum expected network packet size in bytes for
     * SSL/TLS/DTLS records.
     *
     * @apiNote  The implicit size may not be a fixed value, especially
     *           for a DTLS protocols implementation.
     *
     * @implNote For SSL/TLS/DTLS connections, the underlying provider
     *           should calculate and specify the implicit value of the
     *           maximum expected network packet size if it is not
     *           configured explicitly.  For any connection populated
     *           object, this method should never return {@code 0} so
     *           that applications can retrieve the actual implicit size
     *           of the underlying implementation.
     *           <P>
     *           An implementation should attempt to comply with the maximum
     *           packet size configuration.  However, if the maximum packet
     *           size is too small to hold a minimal record, an implementation
     *           may try to generate as minimal records as possible.  This
     *           may cause a generated packet to be larger than the maximum
     *           packet size.
     *
     * @return   the maximum expected network packet size, or {@code 0} if
     *           use the implicit size that is automatically specified by
     *           the underlying implementation and this object has not been
     *           populated by any connection.
     *
     * @see      #setMaximumPacketSize(int)
     *
     * @since 9
     */
    public int getMaximumPacketSize() {
        return maximumPacketSize;
    }

    /**
     * Returns a prioritized array of application-layer protocol names that
     * can be negotiated over the SSL/TLS/DTLS protocols.
     * <p>
     * The array could be empty (zero-length), in which case protocol
     * indications will not be used.
     * <p>
     * This method will return a new array each time it is invoked.
     *
     * @return a non-null, possibly zero-length array of application protocol
     *         {@code String}s.  The array is ordered based on protocol
     *         preference, with the first entry being the most preferred.
     * @see #setApplicationProtocols
     * @since 9
     */
    public String[] getApplicationProtocols() {
        return applicationProtocols.clone();
    }

    /**
     * Sets the prioritized array of application-layer protocol names that
     * can be negotiated over the SSL/TLS/DTLS protocols.
     * <p>
     * If application-layer protocols are supported by the underlying
     * SSL/TLS implementation, this method configures which values can
     * be negotiated by protocols such as <a
     * href="http://www.ietf.org/rfc/rfc7301.txt"> RFC 7301 </a>, the
     * Application Layer Protocol Negotiation (ALPN).
     * <p>
     * If this end of the connection is expected to offer application protocol
     * values, all protocols configured by this method will be sent to the
     * peer.
     * <p>
     * If this end of the connection is expected to select the application
     * protocol value, the {@code protocols} configured by this method are
     * compared with those sent by the peer.  The first matched value becomes
     * the negotiated value.  If none of the {@code protocols} were actually
     * requested by the peer, the underlying protocol will determine what
     * action to take.  (For example, ALPN will send a
     * {@code "no_application_protocol"} alert and terminate the connection.)
     * <p>
     * The {@code String} values must be presented using the network
     * byte representation expected by the peer.  For example, if an ALPN
     * {@code String} should be exchanged using {@code UTF-8}, the
     * {@code String} should be converted to its {@code byte[]} representation
     * and stored as a byte-oriented {@code String} before calling this method.
     * For example:
     *
     * <blockquote><pre>
     *     // Encode 3 Meetei Mayek letters (HUK, UN, I) using Unicode Escapes
     *     //     0xabcd->0xabcf, 2 Unicode bytes/letter.
     *     String HUK_UN_I =  "\u005cuabcd\u005cuabce\u005cuabcf";
     *
     *     // Convert into UTF-8 encoded bytes (3 bytes/letter)
     *     byte[] bytes = HUK_UN_I.getBytes(StandardCharsets.UTF_8);
     *
     *     // Preserve octet byte order by using ISO_8859_1 encoding
     *     String encodedHukUnI =
     *         new String(bytes, StandardCharsets.ISO_8859_1);
     *
     *     // Also, encode a two byte RFC 8701 GREASE ALPN value
     *     //     e.g. 0x0A, 0x1A, 0x2A...0xFA
     *     String rfc8701Grease8A = "\u005cu008A\u005cu008A";
     *
     *     // Set the ALPN vlues on the sslSocket.
     *     SSLParameters p = sslSocket.getSSLParameters();
     *     p.setApplicationProtocols(new String[] {
     *             "h2", "http/1.1", encodedHukUnI, rfc8701Grease8A});
     *     sslSocket.setSSLParameters(p);
     * </pre></blockquote>
     *
     * @implSpec
     * This method will make a copy of the {@code protocols} array.
     *
     * @param protocols   an ordered array of application protocols,
     *                    with {@code protocols[0]} being the most preferred.
     *                    If the array is empty (zero-length), protocol
     *                    indications will not be used.
     * @throws IllegalArgumentException if protocols is null, or if
     *                    any element in a non-empty array is null or an
     *                    empty (zero-length) string
     *
     * @spec https://www.rfc-editor.org/info/rfc7301
     *      RFC 7301: Transport Layer Security (TLS) Application-Layer Protocol Negotiation Extension
     * @see #getApplicationProtocols
     * @since 9
     */
    public void setApplicationProtocols(String[] protocols) {
        if (protocols == null) {
            throw new IllegalArgumentException("protocols was null");
        }

        String[] tempProtocols = protocols.clone();

        for (String p : tempProtocols) {
            if (p == null || p.isEmpty()) {
                throw new IllegalArgumentException(
                    "An element of protocols was null/empty");
            }
        }
        applicationProtocols = tempProtocols;
    }

    /**
     * Returns a prioritized array of signature scheme names that can be used
     * over the SSL/TLS/DTLS protocols.
     * <p>
     * Note that the standard list of signature scheme names are defined in
     * the <a href=
     * "{@docRoot}/../specs/security/standard-names.html#signature-schemes">
     * Signature Schemes</a> section of the Java Security Standard Algorithm
     * Names Specification.  Providers may support signature schemes not defined
     * in this list or may not use the recommended name for a certain
     * signature scheme.
     * <p>
     * The set of signature schemes that will be used over the SSL/TLS/DTLS
     * connections is determined by the returned array of this method and the
     * underlying provider-specific default signature schemes.
     * <p>
     * If the returned array is {@code null}, then the underlying
     * provider-specific default signature schemes will be used over the
     * SSL/TLS/DTLS connections.
     * <p>
     * If the returned array is empty (zero-length), then the signature scheme
     * negotiation mechanism is turned off for SSL/TLS/DTLS protocols, and
     * the connections may not be able to be established if the negotiation
     * mechanism is required by a certain SSL/TLS/DTLS protocol.  This
     * parameter will override the underlying provider-specific default
     * signature schemes.
     * <p>
     * If the returned array is not {@code null} or empty (zero-length),
     * then the signature schemes in the returned array will be used over
     * the SSL/TLS/DTLS connections.  This parameter will override the
     * underlying provider-specific default signature schemes.
     * <p>
     * This method returns the most recent value passed to
     * {@link #setSignatureSchemes} if that method has been called and
     * otherwise returns the default signature schemes for connection
     * populated objects, or {@code null} for pre-populated objects.
     *
     * @apiNote
     * Note that a provider may not have been updated to support this method
     * and in that case may return {@code null} instead of the default
     * signature schemes for connection populated objects.
     *
     * @implNote
     * The SunJSSE provider supports this method.
     *
     * @implNote
     * Note that applications may use the
     * {@systemProperty jdk.tls.client.SignatureSchemes} and/or
     * {@systemProperty jdk.tls.server.SignatureSchemes} system properties
     * with the SunJSSE provider to override the provider-specific default
     * signature schemes.
     *
     * @spec security/standard-names.html Java Security Standard Algorithm Names
     * @return an array of signature scheme {@code Strings} or {@code null} if
     *         none have been set.  For non-null returns, this method will
     *         return a new array each time it is invoked.  The array is
     *         ordered based on signature scheme preference, with the first
     *         entry being the most preferred.  Providers should ignore unknown
     *         signature scheme names while establishing the SSL/TLS/DTLS
     *         connections.
     * @see #setSignatureSchemes
     *
     * @since 19
     */
    public String[] getSignatureSchemes() {
        return clone(signatureSchemes);
    }

    /**
     * Sets the prioritized array of signature scheme names that
     * can be used over the SSL/TLS/DTLS protocols.
     * <p>
     * Note that the standard list of signature scheme names are defined in
     * the <a href=
     * "{@docRoot}/../specs/security/standard-names.html#signature-schemes">
     * Signature Schemes</a> section of the Java Security Standard Algorithm
     * Names Specification.  Providers may support signature schemes not
     * defined in this list or may not use the recommended name for a certain
     * signature scheme.
     * <p>
     * The set of signature schemes that will be used over the SSL/TLS/DTLS
     * connections is determined by the input parameter {@code signatureSchemes}
     * array and the underlying provider-specific default signature schemes.
     * See {@link #getSignatureSchemes} for specific details on how the
     * parameters are used in SSL/TLS/DTLS connections.
     *
     * @apiNote
     * Note that a provider may not have been updated to support this method
     * and in that case may ignore the schemes that are set.
     *
     * @implNote
     * The SunJSSE provider supports this method.
     *
     * @param signatureSchemes an ordered array of signature scheme names with
     *        the first entry being the most preferred, or {@code null}.  This
     *        method will make a copy of this array.  Providers should ignore
     *        unknown signature scheme names while establishing the
     *        SSL/TLS/DTLS connections.
     * @spec security/standard-names.html Java Security Standard Algorithm Names
     * @throws IllegalArgumentException if any element in the
     *        {@code signatureSchemes} array is {@code null} or
     *        {@linkplain String#isBlank() blank}.
     *
     * @see #getSignatureSchemes
     *
     * @since 19
     */
    public void setSignatureSchemes(String[] signatureSchemes) {
        String[] tempSchemes = null;

        if (signatureSchemes != null) {
            tempSchemes = signatureSchemes.clone();
            for (String scheme : tempSchemes) {
                if (scheme == null || scheme.isBlank()) {
                    throw new IllegalArgumentException(
                        "An element of signatureSchemes is null or blank");
                }
            }
        }

        this.signatureSchemes = tempSchemes;
    }

    /**
     * Returns a prioritized array of key exchange named groups names that
     * can be used over the SSL/TLS/DTLS protocols.
     * <p>
     * Note that the standard list of key exchange named groups are defined
     * in the <a href=
     * "{@docRoot}/../specs/security/standard-names.html#named-groups">
     * Named Groups</a> section of the Java Security Standard Algorithm
     * Names Specification.  Providers may support named groups not defined
     * in this list or may not use the recommended name for a certain named
     * group.
     * <p>
     * The set of named groups that will be used over the SSL/TLS/DTLS
     * connections is determined by the returned array of this method and the
     * underlying provider-specific default named groups.
     * <p>
     * If the returned array is {@code null}, then the underlying
     * provider-specific default named groups will be used over the
     * SSL/TLS/DTLS connections.
     * <p>
     * If the returned array is empty (zero-length), then the named group
     * negotiation mechanism is turned off for SSL/TLS/DTLS protocols, and
     * the connections may not be able to be established if the negotiation
     * mechanism is required by a certain SSL/TLS/DTLS protocol.  This
     * parameter will override the underlying provider-specific default
     * name groups.
     * <p>
     * If the returned array is not {@code null} or empty (zero-length),
     * then the named groups in the returned array will be used over
     * the SSL/TLS/DTLS connections.  This parameter will override the
     * underlying provider-specific default named groups.
     * <p>
     * This method returns the most recent value passed to
     * {@link #setNamedGroups} if that method has been called and otherwise
     * returns the default named groups for connection populated objects,
     * or {@code null} for pre-populated objects.
     *
     * @apiNote
     * Note that a provider may not have been updated to support this method
     * and in that case may return {@code null} instead of the default
     * named groups for connection populated objects.
     *
     * @implNote
     * The SunJSSE provider supports this method.
     *
     * @implNote
     * Note that applications may use the
     * {@systemProperty jdk.tls.namedGroups} system property with the SunJSSE
     * provider to override the provider-specific default named groups.
     *
     * @spec security/standard-names.html Java Security Standard Algorithm Names
     * @return an array of key exchange named group names {@code Strings} or
     *         {@code null} if none have been set.  For non-null returns, this
     *         method will return a new array each time it is invoked.  The
     *         array is ordered based on named group preference, with the first
     *         entry being the most preferred.  Providers should ignore unknown
     *         named group names while establishing the SSL/TLS/DTLS
     *         connections.
     * @see #setNamedGroups
     *
     * @since 20
     */
    public String[] getNamedGroups() {
        return clone(namedGroups);
    }

    /**
     * Sets the prioritized array of key exchange named groups names that
     * can be used over the SSL/TLS/DTLS protocols.
     * <p>
     * Note that the standard list of key exchange named groups are defined in
     * the <a href=
     * "{@docRoot}/../specs/security/standard-names.html#named-groups">
     * Named Groups</a> section of the Java Security Standard Algorithm
     * Names Specification.  Providers may support named groups not defined
     * in this list or may not use the recommended name for a certain named
     * group.
     * <p>
     * The set of named groups that will be used over the SSL/TLS/DTLS
     * connections is determined by the input parameter {@code namedGroups}
     * array and the underlying provider-specific default named groups.
     * See {@link #getNamedGroups} for specific details on how the
     * parameters are used in SSL/TLS/DTLS connections.
     *
     * @apiNote
     * Note that a provider may not have been updated to support this method
     * and in that case may ignore the named groups that are set.
     *
     * @implNote
     * The SunJSSE provider supports this method.
     *
     * @param namedGroups an ordered array of key exchange named group names
     *        with the first entry being the most preferred, or {@code null}.
     *        This method will make a copy of this array. Providers should
     *        ignore unknown named group scheme names while establishing the
     *        SSL/TLS/DTLS connections.
     * @spec security/standard-names.html Java Security Standard Algorithm Names
     * @throws IllegalArgumentException if any element in the
     *        {@code namedGroups} array is a duplicate, {@code null} or
     *        {@linkplain String#isBlank() blank}.
     *
     * @see #getNamedGroups
     *
     * @since 20
     */
    public void setNamedGroups(String[] namedGroups) {
        String[] tempGroups = null;

        if (namedGroups != null) {
            tempGroups = namedGroups.clone();
            Set<String> groupsSet = new HashSet<>();
            for (String namedGroup : tempGroups) {
                if (namedGroup == null || namedGroup.isBlank()) {
                    throw new IllegalArgumentException(
                        "An element of namedGroups is null or blank");
                }

                if (groupsSet.contains(namedGroup)) {
                    throw new IllegalArgumentException(
                        "Duplicate element of namedGroups: " + namedGroup);
                }
                groupsSet.add(namedGroup);
            }
        }

        this.namedGroups = tempGroups;
    }
}
