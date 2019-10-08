﻿using System.ComponentModel.DataAnnotations;

using Newtonsoft.Json;

namespace Simple.Models
{
    public class TokenRequest
    {
        [Required]
        [JsonProperty("username")]
        public string Username { get; set; }


        [Required]
        [JsonProperty("password")]
        public string Password { get; set; }
    }
}
