import json
import folium
import os


LOG_FILE = "logs/attacks.json"
MAX_MARKERS = 500


def build_attack_map():

    world_map = folium.Map(
        location=[20, 0],
        zoom_start=2,
        tiles="cartodb dark_matter"
    )

    if not os.path.exists(LOG_FILE):
        return world_map

    marker_count = 0

    with open(LOG_FILE) as f:

        for line in f:

            if marker_count >= MAX_MARKERS:
                break

            try:

                entry = json.loads(line)

                geo = entry.get("geo")

                if not geo:
                    continue

                lat = geo.get("lat")
                lon = geo.get("lon")

                if lat is None or lon is None:
                    continue

                popup = f"""
                IP: {entry.get('ip')}<br>
                Event: {entry.get('event')}<br>
                Action: {entry.get('action')}<br>
                Country: {geo.get('country')}
                """

                folium.CircleMarker(

                    location=[lat, lon],
                    radius=6,
                    color="red",
                    fill=True,
                    fill_color="red",
                    popup=popup

                ).add_to(world_map)

                marker_count += 1

            except json.JSONDecodeError:
                continue
            except Exception:
                continue

    return world_map
