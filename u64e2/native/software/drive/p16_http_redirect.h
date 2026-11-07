#ifndef WIC64_HTTP_REDIRECT_H
#define WIC64_HTTP_REDIRECT_H

#include <cstddef>
#include <cstring>

namespace WiC64 {
    namespace HttpRedirect {
        struct AbsoluteParts {
            size_t schemeColon;
            size_t authorityEnd;
            size_t pathStart;
            size_t pathEnd;
        };

        inline char asciiLower(char value) {
            return value >= 'A' && value <= 'Z'
                ? static_cast<char>(value + ('a' - 'A'))
                : value;
        }

        inline bool startsWithIgnoreCase(
                const char* value,
                size_t length,
                const char* prefix) {
            if (value == NULL || prefix == NULL) return false;
            const size_t prefixLength = std::strlen(prefix);
            if (length < prefixLength) return false;
            for (size_t i = 0; i < prefixLength; ++i) {
                if (asciiLower(value[i]) != asciiLower(prefix[i])) {
                    return false;
                }
            }
            return true;
        }

        inline bool parseAbsoluteHttpUrl(
                const char* value,
                size_t length,
                AbsoluteParts* parts) {
            if (value == NULL || parts == NULL || length == 0) return false;

            size_t schemeColon = 0;
            size_t authorityStart = 0;
            if (startsWithIgnoreCase(value, length, "http://")) {
                schemeColon = 4;
                authorityStart = 7;
            } else if (startsWithIgnoreCase(value, length, "https://")) {
                schemeColon = 5;
                authorityStart = 8;
            } else {
                return false;
            }

            size_t authorityEnd = authorityStart;
            while (authorityEnd < length && value[authorityEnd] != '/' &&
                    value[authorityEnd] != '?' && value[authorityEnd] != '#') {
                const unsigned char byte =
                    static_cast<unsigned char>(value[authorityEnd]);
                if (byte <= 0x20U || byte == 0x7fU ||
                        value[authorityEnd] == '\\') {
                    return false;
                }
                ++authorityEnd;
            }
            if (authorityEnd == authorityStart) return false;

            size_t pathStart = authorityEnd;
            size_t pathEnd = authorityEnd;
            if (pathStart < length && value[pathStart] == '/') {
                pathEnd = pathStart;
                while (pathEnd < length && value[pathEnd] != '?' &&
                        value[pathEnd] != '#') {
                    const unsigned char byte =
                        static_cast<unsigned char>(value[pathEnd]);
                    if (byte <= 0x20U || byte == 0x7fU ||
                            value[pathEnd] == '\\') {
                        return false;
                    }
                    ++pathEnd;
                }
            } else if (pathStart < length && value[pathStart] != '?' &&
                    value[pathStart] != '#') {
                return false;
            }

            for (size_t i = pathEnd; i < length; ++i) {
                const unsigned char byte = static_cast<unsigned char>(value[i]);
                if (byte <= 0x20U || byte == 0x7fU || value[i] == '\\') {
                    return false;
                }
            }

            parts->schemeColon = schemeColon;
            parts->authorityEnd = authorityEnd;
            parts->pathStart = pathStart;
            parts->pathEnd = pathEnd;
            return true;
        }

        inline bool append(
                char* output,
                size_t capacity,
                size_t* length,
                const char* value,
                size_t valueLength) {
            if (output == NULL || length == NULL || value == NULL ||
                    *length > capacity || valueLength >= capacity - *length) {
                return false;
            }
            std::memcpy(output + *length, value, valueLength);
            *length += valueLength;
            output[*length] = '\0';
            return true;
        }

        // Remove literal dot segments in place. Percent-encoded dots are left
        // untouched, as required for URI resolution. Empty segments are kept.
        inline size_t removeDotSegments(
                char* value,
                size_t pathStart,
                size_t pathEnd) {
            if (value == NULL || pathStart >= pathEnd ||
                    value[pathStart] != '/') {
                return pathEnd;
            }

            size_t read = pathStart;
            size_t write = pathStart;
            while (read < pathEnd) {
                ++read; // Every parsed segment begins with '/'.
                const size_t segmentStart = read;
                while (read < pathEnd && value[read] != '/') ++read;
                const size_t segmentLength = read - segmentStart;
                const bool finalSegment = read == pathEnd;

                if (segmentLength == 1 && value[segmentStart] == '.') {
                    // A final dot segment is replaced by an empty segment.
                    // Always append its slash, even when the preceding segment
                    // was already empty.
                    if (finalSegment) value[write++] = '/';
                    continue;
                }

                if (segmentLength == 2 && value[segmentStart] == '.' &&
                        value[segmentStart + 1] == '.') {
                    // Remove exactly one preceding path segment. A trailing
                    // slash represents an empty segment and must not cause the
                    // previous non-empty segment to be removed as well.
                    size_t previousSegment = write;
                    while (previousSegment > pathStart &&
                            value[previousSegment - 1] != '/') {
                        --previousSegment;
                    }
                    if (previousSegment > pathStart) --previousSegment;
                    write = previousSegment;
                    // A final double-dot likewise leaves an empty segment
                    // after removing exactly one predecessor.
                    if (finalSegment) value[write++] = '/';
                    continue;
                }

                value[write++] = '/';
                if (segmentLength > 0) {
                    std::memmove(value + write, value + segmentStart,
                        segmentLength);
                    write += segmentLength;
                }
            }
            return write;
        }

        inline bool resolve(
                const char* base,
                const char* location,
                char* output,
                size_t capacity) {
            if (base == NULL || location == NULL || output == NULL ||
                    capacity == 0) {
                return false;
            }
            output[0] = '\0';

            size_t baseLength = std::strlen(base);
            const char* baseFragment =
                static_cast<const char*>(std::memchr(base, '#', baseLength));
            if (baseFragment != NULL) {
                baseLength = static_cast<size_t>(baseFragment - base);
            }
            AbsoluteParts baseParts;
            if (!parseAbsoluteHttpUrl(base, baseLength, &baseParts)) {
                return false;
            }

            const char* locationStart = location;
            size_t locationLength = std::strlen(location);
            while (locationLength > 0 &&
                    (locationStart[0] == ' ' || locationStart[0] == '\t')) {
                ++locationStart;
                --locationLength;
            }
            while (locationLength > 0 &&
                    (locationStart[locationLength - 1] == ' ' ||
                     locationStart[locationLength - 1] == '\t')) {
                --locationLength;
            }
            const char* fragment = static_cast<const char*>(
                std::memchr(locationStart, '#', locationLength));
            if (fragment != NULL) {
                locationLength = static_cast<size_t>(fragment - locationStart);
            }
            for (size_t i = 0; i < locationLength; ++i) {
                const unsigned char byte =
                    static_cast<unsigned char>(locationStart[i]);
                if (byte <= 0x20U || byte == 0x7fU ||
                        locationStart[i] == '\\') {
                    return false;
                }
            }

            size_t outputLength = 0;
            bool normalizePath = true;
            const bool absoluteHttp =
                startsWithIgnoreCase(locationStart, locationLength,
                    "http://") ||
                startsWithIgnoreCase(locationStart, locationLength,
                    "https://");
            if (absoluteHttp) {
                if (!append(output, capacity, &outputLength,
                        locationStart, locationLength)) {
                    return false;
                }
            } else if (locationLength >= 2 && locationStart[0] == '/' &&
                    locationStart[1] == '/') {
                if (!append(output, capacity, &outputLength, base,
                        baseParts.schemeColon + 1) ||
                        !append(output, capacity, &outputLength,
                            locationStart, locationLength)) {
                    return false;
                }
            } else if (locationLength > 0 && locationStart[0] == '/') {
                if (!append(output, capacity, &outputLength, base,
                        baseParts.authorityEnd) ||
                        !append(output, capacity, &outputLength,
                            locationStart, locationLength)) {
                    return false;
                }
            } else if (locationLength > 0 && locationStart[0] == '?') {
                // RFC 3986 section 5.2.2 inherits the base path byte for byte
                // when the reference path is empty.
                normalizePath = false;
                const size_t basePathEnd = baseParts.pathEnd;
                if (!append(output, capacity, &outputLength,
                        base, basePathEnd) ||
                        !append(output, capacity, &outputLength,
                            locationStart, locationLength)) {
                    return false;
                }
            } else if (locationLength == 0) {
                normalizePath = false;
                if (!append(output, capacity, &outputLength,
                        base, baseLength)) {
                    return false;
                }
            } else {
                // A colon before the first path/query delimiter denotes an
                // unsupported absolute scheme, not a relative path segment.
                for (size_t i = 0; i < locationLength &&
                        locationStart[i] != '/' &&
                        locationStart[i] != '?'; ++i) {
                    if (locationStart[i] == ':') return false;
                }

                size_t baseDirectoryEnd = baseParts.authorityEnd;
                if (baseParts.pathStart < baseParts.pathEnd) {
                    baseDirectoryEnd = baseParts.pathStart + 1;
                    for (size_t i = baseParts.pathStart;
                            i < baseParts.pathEnd; ++i) {
                        if (base[i] == '/') baseDirectoryEnd = i + 1;
                    }
                }
                if (!append(output, capacity, &outputLength, base,
                        baseDirectoryEnd)) {
                    return false;
                }
                if (baseDirectoryEnd == baseParts.authorityEnd &&
                        !append(output, capacity, &outputLength, "/", 1)) {
                    return false;
                }
                if (!append(output, capacity, &outputLength,
                        locationStart, locationLength)) {
                    return false;
                }
            }

            AbsoluteParts outputParts;
            if (!parseAbsoluteHttpUrl(output, outputLength, &outputParts)) {
                output[0] = '\0';
                return false;
            }
            if (normalizePath &&
                    outputParts.pathStart < outputParts.pathEnd) {
                const size_t normalizedPathEnd = removeDotSegments(
                    output, outputParts.pathStart, outputParts.pathEnd);
                if (normalizedPathEnd != outputParts.pathEnd) {
                    std::memmove(output + normalizedPathEnd,
                        output + outputParts.pathEnd,
                        outputLength - outputParts.pathEnd + 1);
                    outputLength -= outputParts.pathEnd - normalizedPathEnd;
                }
            }
            return outputLength > 0 && outputLength < capacity;
        }
    }
}

#endif
