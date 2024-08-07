use base64::encode;
use dotenv::dotenv;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use serde_derive::{Deserialize, Serialize};
use std::collections::HashMap; // Add this import
use std::time::Duration;
use tokio::time::sleep;
use urlencoding;

use anyhow::{Context, Result};
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response, Server};
use std::process::Command;
use std::sync::{Arc, Mutex};

#[derive(Serialize, Deserialize, Debug)]
struct SpotifyAuthResponse {
    access_token: String,
    token_type: String,
    expires_in: u64, // Update this to u64 to match the integer type in the response
}

impl SpotifyAuthResponse {
    async fn get(client_id: &String, secret_id: &String) -> Result<String> {
        // Encode credentials in base64
        let credentials = format!("{}:{}", client_id, secret_id);
        let encoded_credentials = encode(credentials);

        // Create the authorization header value
        let auth_header_value = format!("Basic {}", encoded_credentials);

        // Prepare the form data
        let mut params = HashMap::new();
        params.insert("grant_type", "client_credentials");

        // Build the client and send the POST request
        let client = reqwest::Client::new();
        let response = client
            .post("https://accounts.spotify.com/api/token")
            .header(AUTHORIZATION, auth_header_value)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .form(&params)
            .send()
            .await?;
        let auth_response = response
            .json::<SpotifyAuthResponse>()
            .await
            .context("Failed to parse response body")?;

        Ok(auth_response.access_token)
    }
}

// PLAYLIST STRUCTS
#[derive(Serialize, Deserialize, Debug)]
struct SpotifyPlaylist {
    name: String,
    description: Option<String>,
    tracks: Tracks,
}

#[derive(Serialize, Deserialize, Debug)]
struct Tracks {
    items: Vec<TrackItem>,
    total: u32,           // Total number of tracks in the playlist
    next: Option<String>, // URL to the next page of tracks, if any
}

#[derive(Serialize, Deserialize, Debug)]
struct TrackItem {
    track: Track,
}

#[derive(Serialize, Deserialize, Debug)]
struct Track {
    id: String, // Add this field
    name: String,
    artists: Vec<Artist>,
    album: Album,
}

#[derive(Serialize, Deserialize, Debug)]
struct Artist {
    name: String,
}

#[derive(Serialize, Deserialize, Debug)]
struct Album {
    name: String,
}

fn get_authorization_url(client_id: &str, redirect_uri: &str) -> String {
    let scopes = "user-read-private playlist-modify-public playlist-modify-private";
    let state = "some_random_state"; // You can generate a unique state per session for security

    let encoded_redirect_uri = urlencoding::encode(redirect_uri);

    format!(
        "https://accounts.spotify.com/authorize?response_type=code&client_id={}&scope={}&redirect_uri={}&state={}",
        client_id, scopes, encoded_redirect_uri, state
    )
}

async fn exchange_code_for_token(
    client_id: &str,
    client_secret: &str,
    code: &str,
    redirect_uri: &str,
) -> Result<SpotifyAuthResponse> {
    let client = reqwest::Client::new();
    let credentials = format!("{}:{}", client_id, client_secret);
    let encoded_credentials = base64::encode(credentials);

    let params = [
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri),
    ];

    let response = client
        .post("https://accounts.spotify.com/api/token")
        .header(AUTHORIZATION, format!("Basic {}", encoded_credentials))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .form(&params)
        .send()
        .await?;

    if response.status().is_success() {
        let auth_response = response.json::<SpotifyAuthResponse>().await?;
        Ok(auth_response)
    } else {
        Err(anyhow::anyhow!(
            "Failed to exchange code for token. Status: {}",
            response.status()
        ))
    }
}

impl SpotifyPlaylist {
    async fn fetch_playlist(playlist_id: &str, access_token: &str) -> Result<Vec<TrackItem>> {
        let mut all_tracks = Vec::new();
        let mut next_url = Some(format!(
            "https://api.spotify.com/v1/playlists/{}/tracks",
            playlist_id
        ));
        let client = reqwest::Client::new();

        let delay_duration = Duration::from_millis(500); // 500 milliseconds delay between requests

        while let Some(ref url) = next_url {
            let response = client
                .get(url)
                .header(AUTHORIZATION, format!("Bearer {}", access_token))
                .send()
                .await
                .context("Failed to send request")?;

            if response.status() == 429 {
                if let Some(retry_after) = response.headers().get("Retry-After") {
                    let retry_seconds: u64 = retry_after.to_str()?.parse()?;
                    println!("Rate limited. Retrying after {} seconds...", retry_seconds);
                    sleep(Duration::from_secs(retry_seconds)).await;
                    continue;
                } else {
                    // Default backoff if Retry-After is not provided
                    sleep(Duration::from_secs(1)).await;
                    continue;
                }
            }

            if !response.status().is_success() {
                return Err(anyhow::anyhow!(
                    "Request failed with status: {}",
                    response.status()
                ));
            }

            let playlist_page = response
                .json::<Tracks>()
                .await
                .context("Failed to parse response body")?;

            all_tracks.extend(playlist_page.items);
            next_url = playlist_page.next;

            // Delay before the next request to avoid rate limits
            sleep(delay_duration).await;
        }

        Ok(all_tracks)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct AudioFeatures {
    id: String, // Add this field
    valence: f32,
    energy: f32,
    tempo: f32,
    // Add other audio features as needed
}

async fn fetch_audio_features(
    track_ids: Vec<String>,
    access_token: &str,
) -> Result<Vec<AudioFeatures>> {
    let client = reqwest::Client::new();
    let mut all_features = Vec::new();

    // Process in batches of 100
    for chunk in track_ids.chunks(100) {
        let ids = chunk.join(",");
        let url = format!("https://api.spotify.com/v1/audio-features?ids={}", ids);

        let mut attempts = 0;
        let max_attempts = 5; // Number of retries
        let mut delay = Duration::from_secs(5); // Initial delay between retries

        loop {
            attempts += 1;

            let response = client
                .get(&url)
                .header(AUTHORIZATION, format!("Bearer {}", access_token))
                .send()
                .await
                .context("Failed to fetch audio features")?;

            if response.status().is_success() {
                let response_text = response.text().await?;
                println!("Raw response: {}", response_text);

                let features_response: HashMap<String, Vec<AudioFeatures>> =
                    serde_json::from_str(&response_text)
                        .context("Failed to parse audio features response")?;

                all_features.extend(
                    features_response
                        .get("audio_features")
                        .unwrap_or(&vec![])
                        .to_vec(),
                );
                break;
            } else if response.status().is_server_error() {
                eprintln!(
                    "Server error: {}. Attempt {}/{}. Retrying in {} seconds...",
                    response.status(),
                    attempts,
                    max_attempts,
                    delay.as_secs()
                );

                if attempts >= max_attempts {
                    return Err(anyhow::anyhow!(
                        "Max retry attempts reached. Server is unavailable."
                    ));
                }

                sleep(delay).await;
                delay *= 2; // Exponential backoff
            } else {
                return Err(anyhow::anyhow!(
                    "Failed to fetch audio features. Status: {}",
                    response.status()
                ));
            }
        }
    }

    Ok(all_features)
}

fn categorize_tracks(features: Vec<AudioFeatures>) -> HashMap<String, Vec<String>> {
    let mut categories: HashMap<String, Vec<String>> = HashMap::new();

    for feature in features {
        let category = if feature.valence > 0.75 && feature.energy > 0.6 {
            "Happy"
        } else if feature.valence < 0.4 {
            "Sad"
        } else {
            "Neutral"
        };

        categories
            .entry(category.to_string())
            .or_insert_with(Vec::new)
            .push(feature.id.clone());
    }

    categories
}

async fn create_playlist(user_id: &str, name: &str, access_token: &str) -> Result<String> {
    let client = reqwest::Client::new();
    let url = format!("https://api.spotify.com/v1/users/{}/playlists", user_id);

    let body = serde_json::json!({
        "name": name,
        "description": format!("A {} playlist generated by categorization.", name),
        "public": false
    });

    let response = client
        .post(&url)
        .header(AUTHORIZATION, format!("Bearer {}", access_token))
        .json(&body)
        .send()
        .await
        .context("Failed to create playlist")?;

    // Capture the status code before consuming the response
    let status = response.status();

    // Print the raw response for debugging
    let response_text = response.text().await?;
    println!("Raw response: {}", response_text);

    // Check for success status
    if !status.is_success() {
        return Err(anyhow::anyhow!(
            "Failed to create playlist. Status: {}",
            status
        ));
    }

    let playlist_info: HashMap<String, serde_json::Value> = serde_json::from_str(&response_text)
        .context("Failed to parse playlist creation response")?;

    Ok(playlist_info
        .get("id")
        .unwrap_or(&serde_json::Value::Null)
        .to_string())
}

fn is_valid_spotify_id(id: &str) -> bool {
    let base62_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    id.len() == 22 && id.chars().all(|c| base62_chars.contains(c))
}

// TO-DO: This is just a provisional solution for executing the addition of tracks
// Once I find the better way to do it (solve my skill issue with rust :'D),
// Please remove this function! c:

async fn generate_and_execute_curl_command_for_adding_tracks(
    playlist_id: &str,
    track_ids: Vec<String>,
    access_token: &str,
) -> Result<()> {
    // Validate and format the track URIs
    let valid_uris: Vec<String> = track_ids
        .into_iter()
        .filter(|id| id.len() == 22 && id.chars().all(|c| c.is_ascii_alphanumeric()))
        .map(|id| format!("spotify:track:{}", id))
        .collect();

    if valid_uris.is_empty() {
        println!("No valid URIs to add.");
        return Err(anyhow::anyhow!("No valid track URIs found."));
    }

    // Process in batches of 100
    for chunk in valid_uris.chunks(100) {
        let uris_json = serde_json::to_string(&chunk)?;
        let data = format!(r#"{{"uris":{},"position":0}}"#, uris_json);

        // Generate the curl command
        let curl_command = format!(
            r#"curl --request POST \
  --url https://api.spotify.com/v1/playlists/{}/tracks \
  --header 'Authorization: Bearer {}' \
  --header 'Content-Type: application/json' \
  --data '{}'"#,
            playlist_id, access_token, data
        );

        // Print the curl command to the console
        println!("Generated curl command:\n{}", curl_command);

        // Execute the generated curl command
        let output = Command::new("sh").arg("-c").arg(&curl_command).output()?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        println!("curl output:\n{}", stdout);
        println!("curl error:\n{}", stderr);

        if !output.status.success() {
            return Err(anyhow::anyhow!(
                "Failed to add tracks to playlist with status: {}. Error: {}",
                output.status,
                stderr
            ));
        }
    }

    Ok(())
}

// TO-DO: Make sure I understand why executing this POST request throws an
// "Invalid base62 ID"

async fn add_tracks_to_playlist(
    playlist_id: &str,
    track_ids: Vec<String>,
    access_token: &str,
) -> Result<()> {
    // Validate and format the track URIs
    let valid_uris: Vec<String> = track_ids
        .into_iter()
        .filter(|id| id.len() == 22 && id.chars().all(|c| c.is_ascii_alphanumeric()))
        .map(|id| format!("spotify:track:{}", id))
        .collect();

    if valid_uris.is_empty() {
        println!("No valid URIs to add.");
        return Err(anyhow::anyhow!("No valid track URIs found."));
    }

    // Process in batches of 100
    for chunk in valid_uris.chunks(100) {
        let uris_json = serde_json::to_string(&chunk)?;
        let data = format!(r#"{{"uris":{},"position":0}}"#, uris_json);
        println!("{}", data);
        let output = Command::new("curl")
            .arg("--request")
            .arg("POST")
            .arg(format!(
                "https://api.spotify.com/v1/playlists/{}/tracks",
                playlist_id
            ))
            .arg("--header")
            .arg(format!("Authorization: Bearer {}", access_token))
            .arg("--header")
            .arg("Content-Type: application/json")
            .arg("--data")
            .arg(data)
            .output()
            .expect("Failed to execute curl");

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        println!("curl output:\n{}", stdout);
        println!("curl error:\n{}", stderr);

        if !output.status.success() {
            return Err(anyhow::anyhow!(
                "Failed to add tracks to playlist with status: {}. Error: {}",
                output.status,
                stderr
            ));
        }
    }

    Ok(())
}

async fn get_spotify_user_id(access_token: &str) -> Result<String> {
    let client = reqwest::Client::new();
    let url = "https://api.spotify.com/v1/users/smedjan";

    let response = client
        .get(url)
        .header("Authorization", format!("Bearer {}", access_token))
        .send()
        .await?
        .json::<serde_json::Value>()
        .await?;

    println!("{:?}", response);

    if let Some(user_id) = response["id"].as_str() {
        Ok(user_id.to_string())
    } else {
        Err(anyhow::anyhow!("Could not retrieve user ID"))
    }
}

async fn handle_request(
    req: Request<Body>,
    state: Arc<Mutex<Option<String>>>,
) -> Result<Response<Body>, hyper::Error> {
    // Ensure we're matching the exact path
    if req.uri().path() == "/callback" {
        // Extract the authorization code from the query parameters
        if let Some(query) = req.uri().query() {
            if let Some(code) = query.split('&').find(|param| param.starts_with("code=")) {
                let code = code.trim_start_matches("code=").to_string();
                *state.lock().unwrap() = Some(code);
                return Ok(Response::new(Body::from(
                    "Authorization successful. You can close this window.",
                )));
            }
        }
        return Ok(Response::new(Body::from(
            "Authorization code not found in request.",
        )));
    }

    // If the request is not to /callback, return 404 Not Found
    Ok(Response::builder()
        .status(404)
        .body(Body::from("Not Found"))
        .unwrap())
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenv().ok();
    let client_id = std::env::var("SPOTIFY_CLIENT_ID").context("SPOTIFY_CLIENT_ID not defined")?;
    let client_secret =
        std::env::var("SPOTIFY_SECRET_ID").context("SPOTIFY_SECRET_ID not defined")?;
    let user_id = std::env::var("SPOTIFY_USER_ID").context("SPOTIFY_USER_ID not defined")?;
    let redirect_uri =
        std::env::var("SPOTIFY_REDIRECT_URI").context("SPOTIFY_REDIRECT_URI not defined")?;
    let playlist_id =
        std::env::var("SPOTIFY_PLAYLIST_ID").context("SPOTIFY_PLAYLIST_ID not defined")?;
    let state = Arc::new(Mutex::new(None));

    // Start the local server to handle the callback on port 3000
    let server_state = state.clone();
    let make_svc = make_service_fn(move |_| {
        let server_state = server_state.clone();
        async {
            Ok::<_, hyper::Error>(service_fn(move |req| {
                println!("Received request at path: {}", req.uri().path()); // Debug print
                handle_request(req, server_state.clone())
            }))
        }
    });

    let server = Server::bind(&([127, 0, 0, 1], 8080).into()).serve(make_svc);
    let server_handle = tokio::spawn(server);

    // Generate authorization URL and print it out for the user
    let auth_url = get_authorization_url(&client_id, &redirect_uri);
    println!("Please authorize your app by visiting this URL:");
    println!("{}", auth_url);

    // Wait for the authorization code from the local server
    loop {
        let code = state.lock().unwrap().clone();
        if let Some(code) = code {
            server_handle.abort(); // Stop the server
            let token_response =
                exchange_code_for_token(&client_id, &client_secret, &code, &redirect_uri).await?;
            let access_token = token_response.access_token;
            println!("Access Token: {}", access_token);

            // Fetch playlist details
            let tracks = SpotifyPlaylist::fetch_playlist(playlist_id, &access_token).await?;
            let track_ids: Vec<String> = tracks.into_iter().map(|item| item.track.id).collect();

            // Fetch audio features for the tracks
            let audio_features = fetch_audio_features(track_ids, &access_token).await?;
            let categorized_tracks = categorize_tracks(audio_features);

            // Create new playlists based on the categories and add the tracks
            for (category, track_ids) in categorized_tracks {
                println!("Creating playlist: {}", category);
                let playlist_id = create_playlist(&user_id, &category, &access_token).await?;

                // Clone the track_ids here before moving it to add_tracks_to_playlist
                generate_and_execute_curl_command_for_adding_tracks(
                    &playlist_id,
                    track_ids.clone(),
                    &access_token,
                )
                .await?;

                println!(
                    "Playlist '{}' created with {} tracks.",
                    category,
                    track_ids.len()
                );
            }
            break;
        }
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await; // Polling delay
    }

    Ok(())
}
