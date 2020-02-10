/*
 * GStreamer
 * Copyright (C) 2005 Thomas Vander Stichele <thomas@apestaart.org>
 * Copyright (C) 2005 Ronald S. Bultje <rbultje@ronald.bitfreak.net>
 * Copyright (C) 2020  <<user@hostname.org>>
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Alternatively, the contents of this file may be used under the
 * GNU Lesser General Public License Version 2.1 (the "LGPL"), in
 * which case the following provisions apply instead of the ones
 * mentioned above:
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

/** * SECTION:element-discordcrypto
 *
 * Plugin that handles encryption of opus data so it can be played on a Discord bot
 * https://discordapp.com/developers/docs/topics/voice-connections#establishing-a-voice-udp-connection 
 *
 * <refsect2>
 * <title>Example of playback with ssrc and key being obtained from Discord</title>
 * |[
 * gst-launch-1.0 -v audiotestsrc num-buffers=20 ! audioconvert ! audioresample ! opusenc ! \
 * rtpopuspay pt=120 ssrc=x ! discordcrypto encryption=xsalsa20_poly1305_lite "key=<x,x,x,x,x,x,x,x,x,x,x,x,x,x,x,x,x,x,x,x,x,x,x,x,x,x,x,x,x,x,x,x>" ! udpsink host=127.0.0.1 port=1234
 * ]|
 * </refsect2>
 */

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <string.h>

#include <gst/gst.h>
#include <gst/gsterror.h>

#include <gst/gstparamspecs.h>
#include <gst/base/gstbasetransform.h>
#include <gst/rtp/gstrtpbuffer.h>

#include <sodium.h>

#include "gstdiscordcrypto.h"

GST_DEBUG_CATEGORY_STATIC (gst_discord_crypto_debug);
#define GST_CAT_DEFAULT gst_discord_crypto_debug

enum
{
  PROP_0,
  PROP_ENCRYPTION,
  PROP_KEY
};

/* the capabilities of the inputs and outputs.
 *
 * only accepts opus rtp packets and supplys the same packet 
   with the data encrypted for used with discord
 */
static GstStaticPadTemplate sink_factory = GST_STATIC_PAD_TEMPLATE ("sink",
    GST_PAD_SINK,
    GST_PAD_ALWAYS,
    GST_STATIC_CAPS ("application/x-rtp, "
        "media = (string) \"audio\", "
        "payload = (int) " GST_RTP_PAYLOAD_DYNAMIC_STRING ", "
        "clock-rate = (int) 48000, "
        "encoding-params = (string) \"2\", "
        "encoding-name = (string) { \"OPUS\", \"X-GST-OPUS-DRAFT-SPITTKA-00\" }")
    );

static GstStaticPadTemplate src_factory = GST_STATIC_PAD_TEMPLATE ("src",
    GST_PAD_SRC,
    GST_PAD_ALWAYS,
    GST_STATIC_CAPS ("application/x-rtp, "
        "media = (string) \"audio\", "
        "payload = (int) " GST_RTP_PAYLOAD_DYNAMIC_STRING ", "
        "clock-rate = (int) 48000, "
        "encoding-params = (string) \"2\", "
        "encoding-name = (string) { \"OPUS\", \"X-GST-OPUS-DRAFT-SPITTKA-00\" }")
    );

#define gst_discord_crypto_parent_class parent_class
G_DEFINE_TYPE (GstDiscordcrypto, gst_discord_crypto, GST_TYPE_BASE_TRANSFORM);

static void gst_discord_crypto_set_property (GObject * object, guint prop_id,
    const GValue * value, GParamSpec * pspec);
static void gst_discord_crypto_get_property (GObject * object, guint prop_id,
    GValue * value, GParamSpec * pspec);
static GstFlowReturn gst_discord_crypto_transform (GstBaseTransform * base, 
    GstBuffer *inbuf, GstBuffer *outbuf);
static GstFlowReturn gst_discord_crypto_prepare_output_buffer (GstBaseTransform * base,
    GstBuffer * inbuf, GstBuffer ** outbuf);
static gboolean gst_discord_crypto_start (GstBaseTransform * base);
static gboolean gst_discord_crypto_stop (GstBaseTransform * base);
static gboolean gst_discord_crypto_sink_event (GstPad * pad, GstObject * parent, GstEvent * event);

#define GST_TYPE_DISCORDCRYPTO_PATTERN (gst_discord_crypto_pattern_get_type ())
static GType
gst_discord_crypto_pattern_get_type (void)
{
  static GType discord_crypto_pattern_type = 0;

  if (!discord_crypto_pattern_type) {
    static GEnumValue pattern_types[] = {
      { GST_DISCORDCRYPTO_XSALSA20_POLY1305, "xsalsa20_poly1305", "xsalsa20_poly1305" },
      { GST_DISCORDCRYPTO_XSALSA20_POLY1305_SUFFIX, "xsalsa20_poly1305_suffix", "xsalsa20_poly1305_suffix" },
      { GST_DISCORDCRYPTO_XSALSA20_POLY1305_LITE, "xsalsa20_poly1305_lite", "xsalsa20_poly1305_lite" },
      { 0, NULL, NULL },
    };

    discord_crypto_pattern_type =
      g_enum_register_static ("GstDiscordcryptoPattern", pattern_types);
  }

  return discord_crypto_pattern_type;
}

/* GObject vmethod implementations */

/* initialize the discordcrypto's class */
static void
gst_discord_crypto_class_init (GstDiscordcryptoClass * klass)
{
  GObjectClass *gobject_class;
  GstElementClass *gstelement_class;

  gobject_class = (GObjectClass *) klass;
  gstelement_class = (GstElementClass *) klass;

  gobject_class->set_property = gst_discord_crypto_set_property;
  gobject_class->get_property = gst_discord_crypto_get_property;

  g_object_class_install_property (gobject_class, PROP_ENCRYPTION,
      g_param_spec_enum ("encryption", "Encryption", "type of encryption to use",
       GST_TYPE_DISCORDCRYPTO_PATTERN, GST_DISCORDCRYPTO_XSALSA20_POLY1305_LITE, G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));

  g_object_class_install_property(gobject_class, PROP_KEY,
      gst_param_spec_array("key", "Key", "secret key from discord",
         g_param_spec_uint("value", "val", "val", 0, 255, 0, G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS),
         G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));


  gst_element_class_set_details_simple(gstelement_class,
    "Discord Voice Encrypter",
    "Encryption/Audio",
    "Encrypts opus data for use with Discord",
    "<<user@hostname.org>>");

  gst_element_class_add_pad_template (gstelement_class,
      gst_static_pad_template_get (&src_factory));

  gst_element_class_add_pad_template (gstelement_class,
      gst_static_pad_template_get (&sink_factory));

  GST_BASE_TRANSFORM_CLASS (klass)->transform =
      GST_DEBUG_FUNCPTR (gst_discord_crypto_transform);

  GST_BASE_TRANSFORM_CLASS (klass)->prepare_output_buffer =
      GST_DEBUG_FUNCPTR (gst_discord_crypto_prepare_output_buffer);

  GST_BASE_TRANSFORM_CLASS (klass)->start =
      GST_DEBUG_FUNCPTR (gst_discord_crypto_start);

  GST_BASE_TRANSFORM_CLASS (klass)->stop = 
      GST_DEBUG_FUNCPTR (gst_discord_crypto_stop);
}

/* initialize the new element
 * instantiate pads and add them to element
 * set pad calback functions
 * initialize instance structure
 */
static void
gst_discord_crypto_init (GstDiscordcrypto * filter)
{
  filter->sinkpad = gst_pad_new_from_static_template (&sink_factory, NULL);
  gst_pad_set_event_function (filter->sinkpad,
                              GST_DEBUG_FUNCPTR(gst_discord_crypto_sink_event));

  GST_PAD_SET_PROXY_CAPS (filter->sinkpad);
  gst_element_add_pad (GST_ELEMENT (filter), filter->sinkpad);

  filter->srcpad = gst_pad_new_from_static_template (&src_factory, NULL);
  GST_PAD_SET_PROXY_CAPS (filter->srcpad);
  gst_element_add_pad (GST_ELEMENT (filter), filter->srcpad);

  filter->lite_nonce = 0;
}

static void
gst_discord_crypto_set_property (GObject * object, guint prop_id,
    const GValue * value, GParamSpec * pspec)
{
  GstDiscordcrypto *filter = GST_DISCORDCRYPTO (object);

  switch (prop_id) {
    case PROP_ENCRYPTION:
      filter->encryption = g_value_get_enum (value);
      break;
    case PROP_KEY:
      if (gst_value_array_get_size(value) < 32) {
        GST_ELEMENT_ERROR (filter, LIBRARY, INIT,
          (("Specifed key too short")), (NULL));
        return;
      }
      for (int i = 0; i < 32; i++) {
        const GValue *val = gst_value_array_get_value(value, i);
        filter->key[i] = g_value_get_uint(val);
      }
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
      break;
  }
}

static void
gst_discord_crypto_get_property (GObject * object, guint prop_id,
    GValue * value, GParamSpec * pspec)
{
  GstDiscordcrypto *filter = GST_DISCORDCRYPTO (object);

  GValue val = G_VALUE_INIT;
  g_value_init(&val, G_TYPE_UINT);

  switch (prop_id) {
    case PROP_ENCRYPTION:
      g_value_set_enum (value, filter->encryption);
      break;
    case PROP_KEY:
      for (int i = 0; i < 32; i++) {
        g_value_set_uint(&val, filter->key[i]);
        gst_value_array_append_value(value, &val);
      }
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
      break;
  }

  g_value_unset(&val);
}

/* GstElement vmethod implementations */

/* this function handles sink events */
static gboolean
gst_discord_crypto_sink_event (GstPad * pad, GstObject * parent, GstEvent * event)
{
  gboolean ret;
  switch (GST_EVENT_TYPE (event)) {
    default:
      ret = gst_pad_event_default (pad, parent, event);
      break;
  }
  return ret;
}

/* GstBaseTransform vmethod implementations */
static GstFlowReturn
gst_discord_crypto_transform (GstBaseTransform * base, GstBuffer *inbuf, GstBuffer *outbuf)
{
  GstDiscordcrypto *filter = GST_DISCORDCRYPTO (base);

  GstClockTime timestamp, stream_time;
  GstMapInfo inmap, outmap;

  gst_buffer_map (inbuf, &inmap, GST_MAP_READ);
  gst_buffer_map (outbuf, &outmap, GST_MAP_READWRITE);

  timestamp = GST_BUFFER_TIMESTAMP (inbuf);
  stream_time =
      gst_segment_to_stream_time (&base->segment, GST_FORMAT_TIME, timestamp);

  GST_DEBUG_OBJECT (filter, "sync to %" GST_TIME_FORMAT,
      GST_TIME_ARGS (timestamp));

  if (GST_CLOCK_TIME_IS_VALID (stream_time))
    gst_object_sync_values (GST_OBJECT (filter), stream_time);

  if (!inmap.data || !outmap.data)
    return GST_FLOW_ERROR;

  memcpy(outmap.data, inmap.data, RTP_HEADER_SIZE);

  guint8 nonce[24] = {0};

  guint8 *out_data  = outmap.data + RTP_HEADER_SIZE;
  guint8 *in_data   = inmap.data  + RTP_HEADER_SIZE;
  gsize  data_size  = inmap.size  - RTP_HEADER_SIZE;

  switch (filter->encryption) {
    case GST_DISCORDCRYPTO_XSALSA20_POLY1305:
      memcpy(nonce, inmap.data, RTP_HEADER_SIZE);
      crypto_secretbox_easy(out_data, in_data, data_size, nonce, filter->key);
      break;
    case GST_DISCORDCRYPTO_XSALSA20_POLY1305_SUFFIX:
      randombytes_buf(nonce, sizeof nonce);
      crypto_secretbox_easy(out_data, in_data, data_size, nonce, filter->key);
      memcpy(outmap.data + (filter->outsize - 24), nonce, 24); 
      break;
    case GST_DISCORDCRYPTO_XSALSA20_POLY1305_LITE:
      ((guint32 *)&nonce[0])[0] = g_htonl(filter->lite_nonce);
      if (filter->lite_nonce < 4294967295) {
        filter->lite_nonce++;
      } else {
        filter->lite_nonce = 0;
      }
      crypto_secretbox_easy(out_data, in_data, data_size, nonce, filter->key);
      memcpy(outmap.data + (filter->outsize - 4), &((guint32 *)&nonce[0])[0], 4);
      break;
  }

  gst_buffer_unmap (inbuf, &inmap);
  gst_buffer_unmap (outbuf, &outmap);

  return GST_FLOW_OK;
}

static GstFlowReturn
gst_discord_crypto_prepare_output_buffer (GstBaseTransform * base,
    GstBuffer * inbuf, GstBuffer ** outbuf)
{
  GstDiscordcrypto *filter = GST_DISCORDCRYPTO (base);

  GstClockTime pts, dts, duration;

  pts = GST_BUFFER_PTS (inbuf);
  dts = GST_BUFFER_DTS (inbuf);
  duration = GST_BUFFER_DURATION (inbuf);
  
  gsize in_size = gst_buffer_get_size(inbuf);

  switch (filter->encryption) {
    case GST_DISCORDCRYPTO_XSALSA20_POLY1305:
      filter->outsize = in_size + crypto_secretbox_MACBYTES;
      break;
    case GST_DISCORDCRYPTO_XSALSA20_POLY1305_SUFFIX:
      filter->outsize = in_size + crypto_secretbox_MACBYTES + crypto_secretbox_NONCEBYTES;
      break;
    case GST_DISCORDCRYPTO_XSALSA20_POLY1305_LITE:
      filter->outsize = in_size + crypto_secretbox_MACBYTES + 4;
      break;
  }

  *outbuf = gst_buffer_new_allocate(NULL, filter->outsize, NULL);
  *outbuf = gst_buffer_make_writable (*outbuf);

  GST_BUFFER_PTS (*outbuf) = pts;
  GST_BUFFER_DTS (*outbuf) = dts;
  GST_BUFFER_DURATION (*outbuf) = duration;

  return GST_FLOW_OK;
}

static gboolean
gst_discord_crypto_start (GstBaseTransform * base)
{
  GstDiscordcrypto *filter = GST_DISCORDCRYPTO (base);
  GST_INFO_OBJECT (filter, "Starting");

  GST_INFO_OBJECT (filter, "Initializing libsodium");

  if (sodium_init() == -1) {
    GST_ERROR_OBJECT (filter, "Failed to initialize libsodium");
    return FALSE;
  }

  GST_INFO_OBJECT (filter, "Successfully initialized libsodium");
  return TRUE;
}

static gboolean
gst_discord_crypto_stop (GstBaseTransform * base)
{
  GstDiscordcrypto *filter = GST_DISCORDCRYPTO (base);
  GST_INFO_OBJECT (filter, "Stopping");
  GST_LOG_OBJECT (filter, "Stop successfull");
  return TRUE;
}

/* entry point to initialize the plug-in
 * initialize the plug-in itself
 * register the element factories and other features
 */
static gboolean
discordcrypto_init (GstPlugin * discordcrypto)
{
  /* debug category for fltering log messages
   *
   * exchange the string 'Template discordcrypto' with your description
   */
  GST_DEBUG_CATEGORY_INIT (gst_discord_crypto_debug, "discordcrypto",
      0, "discordcrypto");

  return gst_element_register (discordcrypto, "discordcrypto", GST_RANK_NONE,
      GST_TYPE_DISCORDCRYPTO);
}

/* PACKAGE: this is usually set by autotools depending on some _INIT macro
 * in configure.ac and then written into and defined in config.h, but we can
 * just set it ourselves here in case someone doesn't use autotools to
 * compile this code. GST_PLUGIN_DEFINE needs PACKAGE to be defined.
 */
#ifndef PACKAGE
#define PACKAGE "discordcrypto"
#endif

/* gstreamer looks for this structure to register discordcryptos
 *
 * exchange the string 'Template discordcrypto' with your discordcrypto description
 */
GST_PLUGIN_DEFINE (
    GST_VERSION_MAJOR,
    GST_VERSION_MINOR,
    discordcrypto,
    "discordcrypto",
    discordcrypto_init,
    "0.1",
    "LGPL",
    "GStreamer",
    "http://gstreamer.net/"
)
